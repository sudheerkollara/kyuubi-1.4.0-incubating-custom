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

package org.apache.kyuubi.engine.spark.events

import org.apache.spark.SparkContext
import org.apache.spark.kyuubi.SparkContextHelper

import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.config.KyuubiConf.{ENGINE_EVENT_JSON_LOG_PATH, ENGINE_EVENT_LOGGERS}
import org.apache.kyuubi.engine.spark.events.EventLoggingService._service
import org.apache.kyuubi.events.{AbstractEventLoggingService, EventLoggerType, JsonEventLogger}

class EventLoggingService(spark: SparkContext)
  extends AbstractEventLoggingService[KyuubiSparkEvent] {

  override def initialize(conf: KyuubiConf): Unit = synchronized {
    conf.get(ENGINE_EVENT_LOGGERS)
      .map(EventLoggerType.withName)
      .foreach {
        case EventLoggerType.SPARK =>
          addEventLogger(SparkContextHelper.createSparkHistoryLogger(spark))
        case EventLoggerType.JSON =>
          val jsonEventLogger = new JsonEventLogger[KyuubiSparkEvent](
            spark.applicationAttemptId.getOrElse(spark.applicationId),
            ENGINE_EVENT_JSON_LOG_PATH,
            spark.hadoopConfiguration)
          addService(jsonEventLogger)
          addEventLogger(jsonEventLogger)
        case logger =>
          // TODO: Add more implementations
          throw new IllegalArgumentException(s"Unrecognized event logger: $logger")
      }
    super.initialize(conf)
  }

  override def start(): Unit = synchronized {
    super.start()
    // expose the event logging service only when the loggers successfully start
    _service = Some(this)
  }

  override def stop(): Unit = synchronized {
    _service = None
    super.stop()
  }

}

object EventLoggingService {

  private var _service: Option[EventLoggingService] = None

  def onEvent(event: KyuubiSparkEvent): Unit = {
    _service.foreach(_.onEvent(event))
  }
}
