/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.ha.client

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

import scala.collection.JavaConverters._

import com.google.common.annotations.VisibleForTesting
import org.apache.curator.framework.CuratorFramework
import org.apache.curator.framework.recipes.nodes.PersistentNode
import org.apache.curator.framework.state.{ConnectionState, ConnectionStateListener}
import org.apache.curator.framework.state.ConnectionState.{CONNECTED, LOST, RECONNECTED}
import org.apache.curator.utils.ZKPaths
import org.apache.zookeeper.{CreateMode, KeeperException, WatchedEvent, Watcher}
import org.apache.zookeeper.CreateMode.PERSISTENT
import org.apache.zookeeper.KeeperException.NodeExistsException

import org.apache.kyuubi.{KYUUBI_VERSION, KyuubiException, Logging}
import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.ha.HighAvailabilityConf._
import org.apache.kyuubi.service.{AbstractService, FrontendService}
import org.apache.kyuubi.util.{KyuubiHadoopUtils, ThreadUtils}

/**
 * A abstract service for service discovery
 *
 * @param name   the name of the service itself
 * @param fe the frontend service to publish for service discovery
 */
abstract class ServiceDiscovery(
    name: String,
    fe: FrontendService) extends AbstractService(name) {

  import ServiceDiscovery._
  import ZooKeeperClientProvider._

  private var _zkClient: CuratorFramework = _
  private var _serviceNode: PersistentNode = _

  /**
   * a pre-defined namespace used to publish the instance of the associate service
   */
  private var _namespace: String = _

  def zkClient: CuratorFramework = _zkClient

  def serviceNode: PersistentNode = _serviceNode

  def namespace: String = _namespace

  override def initialize(conf: KyuubiConf): Unit = {
    this.conf = conf
    _namespace = conf.get(HA_ZK_NAMESPACE)
    val maxSleepTime = conf.get(HA_ZK_CONN_MAX_RETRY_WAIT)
    val maxRetries = conf.get(HA_ZK_CONN_MAX_RETRIES)
    _zkClient = buildZookeeperClient(conf)
    zkClient.getConnectionStateListenable.addListener(new ConnectionStateListener {
      private val isConnected = new AtomicBoolean(false)

      override def stateChanged(client: CuratorFramework, newState: ConnectionState): Unit = {
        info(s"Zookeeper client connection state changed to: $newState")
        newState match {
          case CONNECTED | RECONNECTED => isConnected.set(true)
          case LOST =>
            isConnected.set(false)
            val delay = maxRetries.toLong * maxSleepTime
            connectionChecker.schedule(
              new Runnable {
                override def run(): Unit = if (!isConnected.get()) {
                  error(s"Zookeeper client connection state changed to: $newState, but failed to" +
                    s" reconnect in ${delay / 1000} seconds. Give up retry. ")
                  stopGracefully()
                }
              },
              delay,
              TimeUnit.MILLISECONDS)
          case _ =>
        }
      }
    })
    zkClient.start()
    super.initialize(conf)
  }

  override def start(): Unit = {
    val instance = fe.connectionUrl
    _serviceNode = createServiceNode(conf, zkClient, namespace, instance)
    // Set a watch on the serviceNode
    val watcher = new DeRegisterWatcher
    if (zkClient.checkExists.usingWatcher(watcher).forPath(serviceNode.getActualPath) == null) {
      // No node exists, throw exception
      throw new KyuubiException(s"Unable to create znode for this Kyuubi " +
        s"instance[${fe.connectionUrl}] on ZooKeeper.")
    }
    super.start()
  }

  override def stop(): Unit = {
    closeServiceNode()
    if (zkClient != null) zkClient.close()
    super.stop()
  }

  // close the EPHEMERAL_SEQUENTIAL node in zk
  protected def closeServiceNode(): Unit = {
    if (_serviceNode != null) {
      try {
        _serviceNode.close()
      } catch {
        case e: IOException =>
          error("Failed to close the persistent ephemeral znode" + serviceNode.getActualPath, e)
      } finally {
        _serviceNode = null
      }
    }
  }

  // stop the server genteelly
  def stopGracefully(): Unit = {
    stop()
    while (fe.be != null && fe.be.sessionManager.getOpenSessionCount > 0) {
      Thread.sleep(1000 * 60)
    }
    fe.serverable.stop()
  }

  class DeRegisterWatcher extends Watcher {
    override def process(event: WatchedEvent): Unit = {
      if (event.getType == Watcher.Event.EventType.NodeDeleted) {
        warn(s"This Kyuubi instance ${fe.connectionUrl} is now de-registered from" +
          s" ZooKeeper. The server will be shut down after the last client session completes.")
        stopGracefully()
      }
    }
  }

}

object ServiceDiscovery extends Logging {

  final private lazy val connectionChecker =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor("zk-connection-checker")

  def supportServiceDiscovery(conf: KyuubiConf): Boolean = {
    val zkEnsemble = conf.get(HA_ZK_QUORUM)
    zkEnsemble != null && zkEnsemble.nonEmpty
  }

  def getServerHost(zkClient: CuratorFramework, namespace: String): Option[(String, Int)] = {
    // TODO: use last one because to avoid touching some maybe-crashed engines
    // We need a big improvement here.
    getServiceNodesInfo(zkClient, namespace, Some(1), silent = true) match {
      case Seq(sn) => Some((sn.host, sn.port))
      case _ => None
    }
  }

  def getEngineByRefId(
      zkClient: CuratorFramework,
      namespace: String,
      engineRefId: String): Option[(String, Int)] = {
    getServiceNodesInfo(zkClient, namespace, silent = true)
      .find(_.engineRefId.exists(_.equals(engineRefId)))
      .map(data => (data.host, data.port))
  }

  def getServiceNodesInfo(
      zkClient: CuratorFramework,
      namespace: String,
      sizeOpt: Option[Int] = None,
      silent: Boolean = false): Seq[ServiceNodeInfo] = {
    try {
      val hosts = zkClient.getChildren.forPath(namespace)
      val size = sizeOpt.getOrElse(hosts.size())
      hosts.asScala.takeRight(size).map { p =>
        val path = ZKPaths.makePath(namespace, p)
        val instance = new String(zkClient.getData.forPath(path), StandardCharsets.UTF_8)
        val (host, port) = parseInstanceHostPort(instance)
        val version = p.split(";").find(_.startsWith("version=")).map(_.stripPrefix("version="))
        val engineRefId = p.split(";").find(_.startsWith("refId=")).map(_.stripPrefix("refId="))
        info(s"Get service instance:$instance and version:$version under $namespace")
        ServiceNodeInfo(namespace, p, host, port, version, engineRefId)
      }
    } catch {
      case _: Exception if silent => Nil
      case e: Exception =>
        error(s"Failed to get service node info", e)
        Nil
    }
  }

  @VisibleForTesting
  private[client] def parseInstanceHostPort(instance: String): (String, Int) = {
    val maybeInfos = instance.split(";")
      .map(_.split("=", 2))
      .filter(_.size == 2)
      .map(i => (i(0), i(1)))
      .toMap
    if (maybeInfos.size > 0) {
      (
        maybeInfos.get("hive.server2.thrift.bind.host").get,
        maybeInfos.get("hive.server2.thrift.port").get.toInt)
    } else {
      val strings = instance.split(":")
      (strings(0), strings(1).toInt)
    }
  }

  def createAndGetServiceNode(
      conf: KyuubiConf,
      zkClient: CuratorFramework,
      namespace: String,
      instance: String,
      version: Option[String] = None,
      external: Boolean = false): String = {
    createServiceNode(conf, zkClient, namespace, instance, version, external).getActualPath
  }

  private def createServiceNode(
      conf: KyuubiConf,
      zkClient: CuratorFramework,
      namespace: String,
      instance: String,
      version: Option[String] = None,
      external: Boolean = false): PersistentNode = {
    val ns = ZKPaths.makePath(null, namespace)
    try {
      zkClient
        .create()
        .creatingParentsIfNeeded()
        .withMode(PERSISTENT)
        .forPath(ns)
    } catch {
      case _: NodeExistsException => // do nothing
      case e: KeeperException =>
        throw new KyuubiException(s"Failed to create namespace '$ns'", e)
    }

    val session = conf.get(HA_ZK_ENGINE_REF_ID)
      .map(refId => s"refId=$refId;").getOrElse("")
    val pathPrefix = ZKPaths.makePath(
      namespace,
      s"serviceUri=$instance;version=${version.getOrElse(KYUUBI_VERSION)};${session}sequence=")
    var serviceNode: PersistentNode = null
    val createMode =
      if (external) CreateMode.PERSISTENT_SEQUENTIAL
      else CreateMode.EPHEMERAL_SEQUENTIAL
    val znodeData =
      if (conf.get(HA_ZK_PUBLIST_CONFIGS) && session.isEmpty) {
        addConfsToPublish(conf, instance)
      } else {
        instance
      }
    try {
      serviceNode = new PersistentNode(
        zkClient,
        createMode,
        false,
        pathPrefix,
        znodeData.getBytes(StandardCharsets.UTF_8))
      serviceNode.start()
      val znodeTimeout = conf.get(HA_ZK_NODE_TIMEOUT)
      if (!serviceNode.waitForInitialCreate(znodeTimeout, TimeUnit.MILLISECONDS)) {
        throw new KyuubiException(s"Max znode creation wait time $znodeTimeout s exhausted")
      }
      info(s"Created a ${serviceNode.getActualPath} on ZooKeeper for KyuubiServer uri: " + instance)
    } catch {
      case e: Exception =>
        if (serviceNode != null) {
          serviceNode.close()
        }
        throw new KyuubiException(
          s"Unable to create a znode for this server instance: $instance",
          e)
    }
    serviceNode
  }

  /**
   * Refer to the implementation of HIVE-11581 to simplify user connection parameters.
   * https://issues.apache.org/jira/browse/HIVE-11581
   * HiveServer2 should store connection params in ZK
   * when using dynamic service discovery for simpler client connection string.
   */
  private def addConfsToPublish(conf: KyuubiConf, instance: String): String = {
    if (!instance.contains(":")) {
      return instance
    }
    val hostPort = instance.split(":", 2)
    val confsToPublish = collection.mutable.Map[String, String]()

    // Hostname
    confsToPublish += ("hive.server2.thrift.bind.host" -> hostPort(0))
    // Transport mode
    confsToPublish += ("hive.server2.transport.mode" -> "binary")
    // Transport specific confs
    confsToPublish += ("hive.server2.thrift.port" -> hostPort(1))
    confsToPublish += ("hive.server2.thrift.sasl.qop" -> conf.get(KyuubiConf.SASL_QOP))
    // Auth specific confs
    val authenticationMethod = conf.get(KyuubiConf.AUTHENTICATION_METHOD).mkString(",")
    confsToPublish += ("hive.server2.authentication" -> authenticationMethod)
    if (authenticationMethod.equalsIgnoreCase("KERBEROS")) {
      confsToPublish += ("hive.server2.authentication.kerberos.principal" ->
        conf.get(KyuubiConf.SERVER_PRINCIPAL).map(KyuubiHadoopUtils.getServerPrincipal)
          .getOrElse(""))
    }
    confsToPublish.map { case (k, v) => k + "=" + v }.mkString(";")
  }
}

case class ServiceNodeInfo(
    namespace: String,
    nodeName: String,
    host: String,
    port: Int,
    version: Option[String],
    engineRefId: Option[String]) {
  def instance: String = s"$host:$port"
}
