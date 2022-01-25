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

package org.apache.kyuubi.server.mysql.constant

sealed abstract class MySQLCommandPacketType(val value: Int)

object MySQLCommandPacketType {

  // https://dev.mysql.com/doc/internals/en/com-sleep.html
  object COM_SLEEP extends MySQLCommandPacketType(0x00)

  // https://dev.mysql.com/doc/internals/en/com-quit.html
  object COM_QUIT extends MySQLCommandPacketType(0x01)

  // https://dev.mysql.com/doc/internals/en/com-init-db.html
  object COM_INIT_DB extends MySQLCommandPacketType(0x02)

  // https://dev.mysql.com/doc/internals/en/com-query.html
  object COM_QUERY extends MySQLCommandPacketType(0x03)

  // https://dev.mysql.com/doc/internals/en/com-field-list.html
  object COM_FIELD_LIST extends MySQLCommandPacketType(0x04)

  // https://dev.mysql.com/doc/internals/en/com-create-db.html
  object COM_CREATE_DB extends MySQLCommandPacketType(0x05)

  // https://dev.mysql.com/doc/internals/en/com-drop-db.html
  object COM_DROP_DB extends MySQLCommandPacketType(0x06)

  // https://dev.mysql.com/doc/internals/en/com-refresh.html
  object COM_REFRESH extends MySQLCommandPacketType(0x07)

  // https://dev.mysql.com/doc/internals/en/com-shutdown.html
  object COM_SHUTDOWN extends MySQLCommandPacketType(0x08)

  // https://dev.mysql.com/doc/internals/en/com-statistics.html
  object COM_STATISTICS extends MySQLCommandPacketType(0x09)

  // https://dev.mysql.com/doc/internals/en/com-process-info.html
  object COM_PROCESS_INFO extends MySQLCommandPacketType(0x0A)

  // https://dev.mysql.com/doc/internals/en/com-connect.html
  object COM_CONNECT extends MySQLCommandPacketType(0x0B)

  // https://dev.mysql.com/doc/internals/en/com-process-kill.html
  object COM_PROCESS_KILL extends MySQLCommandPacketType(0x0C)

  // https://dev.mysql.com/doc/internals/en/com-debug.html
  object COM_DEBUG extends MySQLCommandPacketType(0x0D)

  // https://dev.mysql.com/doc/internals/en/com-ping.html
  object COM_PING extends MySQLCommandPacketType(0x0E)

  // https://dev.mysql.com/doc/internals/en/com-time.html
  object COM_TIME extends MySQLCommandPacketType(0x0F)

  // https://dev.mysql.com/doc/internals/en/com-delayed-insert.html
  object COM_DELAYED_INSERT extends MySQLCommandPacketType(0x10)

  // https://dev.mysql.com/doc/internals/en/com-change-user.html
  object COM_CHANGE_USER extends MySQLCommandPacketType(0x11)

  // https://dev.mysql.com/doc/internals/en/com-binlog-dump.html
  object COM_BINLOG_DUMP extends MySQLCommandPacketType(0x12)

  // https://dev.mysql.com/doc/internals/en/com-table-dump.html
  object COM_TABLE_DUMP extends MySQLCommandPacketType(0x13)

  // https://dev.mysql.com/doc/internals/en/com-connect-out.html
  object COM_CONNECT_OUT extends MySQLCommandPacketType(0x14)

  // https://dev.mysql.com/doc/internals/en/com-register-slave.html
  object COM_REGISTER_SLAVE extends MySQLCommandPacketType(0x15)

  // https://dev.mysql.com/doc/internals/en/com-stmt-prepare.html
  object COM_STMT_PREPARE extends MySQLCommandPacketType(0x16)

  // https://dev.mysql.com/doc/internals/en/com-stmt-execute.html
  object COM_STMT_EXECUTE extends MySQLCommandPacketType(0x17)

  // https://dev.mysql.com/doc/internals/en/com-stmt-send-long-data.html
  object COM_STMT_SEND_LONG_DATA extends MySQLCommandPacketType(0x18)

  // https://dev.mysql.com/doc/internals/en/com-stmt-close.html
  object COM_STMT_CLOSE extends MySQLCommandPacketType(0x19)

  // https://dev.mysql.com/doc/internals/en/com-stmt-reset.html
  object COM_STMT_RESET extends MySQLCommandPacketType(0x1A)

  // https://dev.mysql.com/doc/internals/en/com-set-option.html
  object COM_SET_OPTION extends MySQLCommandPacketType(0x1B)

  // https://dev.mysql.com/doc/internals/en/com-stmt-fetch.html
  object COM_STMT_FETCH extends MySQLCommandPacketType(0x1C)

  // https://dev.mysql.com/doc/internals/en/com-daemon.html
  object COM_DAEMON extends MySQLCommandPacketType(0x1D)

  // https://dev.mysql.com/doc/internals/en/com-binlog-dump-gtid.html
  object COM_BINLOG_DUMP_GTID extends MySQLCommandPacketType(0x1E)

  // https://dev.mysql.com/doc/internals/en/com-reset-connection.html
  object COM_RESET_CONNECTION extends MySQLCommandPacketType(0x1F)

  def valueOf(value: Int): MySQLCommandPacketType = value match {
    case COM_SLEEP.value => COM_SLEEP
    case COM_QUIT.value => COM_QUIT
    case COM_INIT_DB.value => COM_INIT_DB
    case COM_QUERY.value => COM_QUERY
    case COM_FIELD_LIST.value => COM_FIELD_LIST
    case COM_CREATE_DB.value => COM_CREATE_DB
    case COM_DROP_DB.value => COM_DROP_DB
    case COM_REFRESH.value => COM_REFRESH
    case COM_SHUTDOWN.value => COM_SHUTDOWN
    case COM_STATISTICS.value => COM_STATISTICS
    case COM_PROCESS_INFO.value => COM_PROCESS_INFO
    case COM_CONNECT.value => COM_CONNECT
    case COM_PROCESS_KILL.value => COM_PROCESS_KILL
    case COM_DEBUG.value => COM_DEBUG
    case COM_PING.value => COM_PING
    case COM_TIME.value => COM_TIME
    case COM_DELAYED_INSERT.value => COM_DELAYED_INSERT
    case COM_CHANGE_USER.value => COM_CHANGE_USER
    case COM_BINLOG_DUMP.value => COM_BINLOG_DUMP
    case COM_TABLE_DUMP.value => COM_TABLE_DUMP
    case COM_CONNECT_OUT.value => COM_CONNECT_OUT
    case COM_REGISTER_SLAVE.value => COM_REGISTER_SLAVE
    case COM_STMT_PREPARE.value => COM_STMT_PREPARE
    case COM_STMT_EXECUTE.value => COM_STMT_EXECUTE
    case COM_STMT_SEND_LONG_DATA.value => COM_STMT_SEND_LONG_DATA
    case COM_STMT_CLOSE.value => COM_STMT_CLOSE
    case COM_STMT_RESET.value => COM_STMT_RESET
    case COM_SET_OPTION.value => COM_SET_OPTION
    case COM_STMT_FETCH.value => COM_STMT_FETCH
    case COM_DAEMON.value => COM_DAEMON
    case COM_BINLOG_DUMP_GTID.value => COM_BINLOG_DUMP_GTID
    case COM_RESET_CONNECTION.value => COM_RESET_CONNECTION
  }
}
