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

package org.apache.kyuubi.operation

import java.nio.file.Files

import org.apache.kyuubi.{Utils, WithKyuubiServer}
import org.apache.kyuubi.config.KyuubiConf

class KyuubiOperationHiveCatalogSuite extends WithKyuubiServer with HiveMetadataTests {

  private val metastore = {
    val dir = Utils.createTempDir()
    Files.deleteIfExists(dir)
    dir
  }

  override protected def jdbcUrl: String = getJdbcUrl

  override protected val conf: KyuubiConf = {
    KyuubiConf()
      .set(KyuubiConf.ENGINE_SHARE_LEVEL, "server")
      .set("spark.sql.catalogImplementation", "hive")
      .set(
        "spark.hadoop.javax.jdo.option.ConnectionURL",
        s"jdbc:derby:;databaseName=$metastore;create=true")
  }
}
