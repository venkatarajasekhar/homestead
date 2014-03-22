/**
 * @file handlers_icscf.cpp handlers for UARs and LIRs
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#include "handlers.h"
#include "xmlutils.h"
#include "servercapabilities.h"

#include "log.h"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidxml/rapidxml.hpp"
#include "boost/algorithm/string/join.hpp"

const static HssCacheHandler::StatsFlags SUBSCRIPTION_STATS =
  static_cast<HssCacheHandler::StatsFlags>(
    HssCacheHandler::STAT_HSS_LATENCY |
    HssCacheHandler::STAT_HSS_SUBSCRIPTION_LATENCY);

//
// IMPI Registration Status handling
//

void ImpiRegistrationStatusHandler::run()
{
  if (_cfg->hss_configured)
  {
    const std::string prefix = "/impi/";
    std::string path = _req.path();
    _impi = path.substr(prefix.length(), path.find_first_of("/", prefix.length()) - prefix.length());
    _impu = _req.param("impu");
    _visited_network = _req.param("visited-network");
    if (_visited_network.empty())
    {
      _visited_network = _dest_realm;
    }
    _authorization_type = _req.param("auth-type");
    LOG_DEBUG("Parsed HTTP request: private ID %s, public ID %s, visited network %s, authorization type %s",
              _impi.c_str(), _impu.c_str(), _visited_network.c_str(), _authorization_type.c_str());

    Cx::UserAuthorizationRequest uar(_dict,
                                     _diameter_stack,
                                     _dest_host,
                                     _dest_realm,
                                     _impi,
                                     _impu,
                                     _visited_network,
                                     _authorization_type);
    DiameterTransaction* tsx =
      new DiameterTransaction(_dict, this, SUBSCRIPTION_STATS);
    tsx->set_response_clbk(&ImpiRegistrationStatusHandler::on_uar_response);
    uar.send(tsx, 200);
  }
  else
  {
    LOG_DEBUG("No HSS configured - fake response for server %s", _server_name.c_str());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.String(JSON_RC.c_str());
    writer.Int(DIAMETER_SUCCESS);
    writer.String(JSON_SCSCF.c_str());
    writer.String(_server_name.c_str());
    writer.EndObject();
    _req.add_content(sb.GetString());
    _req.send_reply(200);
    delete this;
  }
}

void ImpiRegistrationStatusHandler::on_uar_response(Diameter::Message& rsp)
{
  Cx::UserAuthorizationAnswer uaa(rsp);
  int32_t result_code = 0;
  uaa.result_code(result_code);
  int32_t experimental_result_code = uaa.experimental_result_code();
  LOG_DEBUG("Received User-Authorization answer with result %d/%d",
            result_code, experimental_result_code);
  if ((result_code == DIAMETER_SUCCESS) ||
      (experimental_result_code == DIAMETER_FIRST_REGISTRATION) ||
      (experimental_result_code == DIAMETER_SUBSEQUENT_REGISTRATION))
  {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.String(JSON_RC.c_str());
    writer.Int(result_code ? result_code : experimental_result_code);
    std::string server_name;
    // If the HSS returned a server_name, return that. If not, return the
    // server capabilities, even if none are returned by the HSS.
    if (uaa.server_name(server_name))
    {
      LOG_DEBUG("Got Server-Name %s", server_name.c_str());
      writer.String(JSON_SCSCF.c_str());
      writer.String(server_name.c_str());
    }
    else
    {
      LOG_DEBUG("Got Server-Capabilities");
      ServerCapabilities server_capabilities = uaa.server_capabilities();
      server_capabilities.write_capabilities(&writer);
    }
    writer.EndObject();
    _req.add_content(sb.GetString());
    _req.send_reply(200);
  }
  else if ((experimental_result_code == DIAMETER_ERROR_USER_UNKNOWN) ||
           (experimental_result_code == DIAMETER_ERROR_IDENTITIES_DONT_MATCH))
  {
    LOG_INFO("User unknown or public/private ID conflict - reject");
    _req.send_reply(404);
  }
  else if ((result_code == DIAMETER_AUTHORIZATION_REJECTED) ||
           (experimental_result_code == DIAMETER_ERROR_ROAMING_NOT_ALLOWED))
  {
    LOG_INFO("Authorization rejected due to roaming not allowed - reject");
    _req.send_reply(403);
  }
  else if (result_code == DIAMETER_TOO_BUSY)
  {
    LOG_INFO("HSS busy - reject");
    _req.send_reply(503);
  }
  else
  {
    LOG_INFO("User-Authorization answer with result %d/%d - reject",
             result_code, experimental_result_code);
    _req.send_reply(500);
  }
  delete this;
}

//
// IMPU Location Information handling
//

void ImpuLocationInfoHandler::run()
{
  if (_cfg->hss_configured)
  {
    const std::string prefix = "/impu/";
    std::string path = _req.path();

    _impu = path.substr(prefix.length(), path.find_first_of("/", prefix.length()) - prefix.length());
    _originating = _req.param("originating");
    _authorization_type = _req.param("auth-type");
    LOG_DEBUG("Parsed HTTP request: public ID %s, originating %s, authorization type %s",
              _impu.c_str(), _originating.c_str(), _authorization_type.c_str());

    Cx::LocationInfoRequest lir(_dict,
                                _diameter_stack,
                                _dest_host,
                                _dest_realm,
                                _originating,
                                _impu,
                                _authorization_type);
    DiameterTransaction* tsx =
      new DiameterTransaction(_dict, this, SUBSCRIPTION_STATS);
    tsx->set_response_clbk(&ImpuLocationInfoHandler::on_lir_response);
    lir.send(tsx, 200);
  }
  else
  {
    LOG_DEBUG("No HSS configured - fake response for server %s", _server_name.c_str());
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.String(JSON_RC.c_str());
    writer.Int(DIAMETER_SUCCESS);
    writer.String(JSON_SCSCF.c_str());
    writer.String(_server_name.c_str());
    writer.EndObject();
    _req.add_content(sb.GetString());
    _req.send_reply(200);
    delete this;
  }
}

void ImpuLocationInfoHandler::on_lir_response(Diameter::Message& rsp)
{
  Cx::LocationInfoAnswer lia(rsp);
  int32_t result_code = 0;
  lia.result_code(result_code);
  int32_t experimental_result_code = lia.experimental_result_code();
  LOG_DEBUG("Received Location-Info answer with result %d/%d",
            result_code, experimental_result_code);
  if ((result_code == DIAMETER_SUCCESS) ||
      (experimental_result_code == DIAMETER_UNREGISTERED_SERVICE))
  {
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    writer.StartObject();
    writer.String(JSON_RC.c_str());
    writer.Int(result_code ? result_code : experimental_result_code);
    std::string server_name;

    // If the HSS returned a server_name, return that. If not, return the
    // server capabilities, even if none are returned by the HSS.
    if ((result_code == DIAMETER_SUCCESS) && (lia.server_name(server_name)))
    {
      LOG_DEBUG("Got Server-Name %s", server_name.c_str());
      writer.String(JSON_SCSCF.c_str());
      writer.String(server_name.c_str());
    }
    else
    {
      LOG_DEBUG("Got Server-Capabilities");
      ServerCapabilities server_capabilities = lia.server_capabilities();
      server_capabilities.write_capabilities(&writer);
    }
    writer.EndObject();
    _req.add_content(sb.GetString());
    _req.send_reply(200);
  }
  else if ((experimental_result_code == DIAMETER_ERROR_USER_UNKNOWN) ||
           (experimental_result_code == DIAMETER_ERROR_IDENTITY_NOT_REGISTERED))
  {
    LOG_INFO("User unknown or public/private ID conflict - reject");
    _req.send_reply(404);
  }
  else if (result_code == DIAMETER_TOO_BUSY)
  {
    LOG_INFO("HSS busy - reject");
    _req.send_reply(503);
  }
  else
  {
    LOG_INFO("Location-Info answer with result %d/%d - reject",
             result_code, experimental_result_code);
    _req.send_reply(500);
  }
  delete this;
}
