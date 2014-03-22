/**
 * @file handlers_requests.cpp handlers for PPRs and RTRs
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

#include "log.h"

#include "boost/algorithm/string/join.hpp"

void RegistrationTerminationHandler::run()
{
  Cx::RegistrationTerminationRequest rtr(_msg);

  // Save off the deregistration reason and all private and public
  // identities on the request.
  _deregistration_reason = rtr.deregistration_reason();
  std::string impi = rtr.impi();
  _impis.push_back(impi);
  std::vector<std::string> associated_identities = rtr.associated_identities();
  _impis.insert(_impis.end(), associated_identities.begin(), associated_identities.end());
  if ((_deregistration_reason != SERVER_CHANGE) &&
      (_deregistration_reason != NEW_SERVER_ASSIGNED))
  {
    // We're not interested in the public identities on the request
    // if deregistration reason is SERVER_CHANGE or NEW_SERVER_ASSIGNED.
    // We'll find some public identities later, and we want _impus to be empty
    // for now.
    _impus = rtr.impus();
  }

  LOG_INFO("Received Regestration-Termination request with dereg reason %d",
           _deregistration_reason);

  if ((_impus.empty()) && ((_deregistration_reason == PERMANENT_TERMINATION) ||
                           (_deregistration_reason == REMOVE_SCSCF) ||
                           (_deregistration_reason == SERVER_CHANGE) ||
                           (_deregistration_reason == NEW_SERVER_ASSIGNED)))
  {
    // Find all the default public identities associated with the
    // private identities specified on the request.
    std::string impis_string = boost::algorithm::join(_impis, ", ");
    LOG_DEBUG("Finding associated default public identities for impis %s", impis_string.c_str());
    Cache::Request* get_associated_impus = _cfg->cache->create_GetAssociatedPrimaryPublicIDs(_impis);
    CacheTransaction* tsx = new CacheTransaction(this);
    tsx->set_success_clbk(&RegistrationTerminationHandler::get_assoc_primary_public_ids_success);
    tsx->set_failure_clbk(&RegistrationTerminationHandler::get_assoc_primary_public_ids_failure);
    _cfg->cache->send(tsx, get_associated_impus);
  }
  else if ((!_impus.empty()) && ((_deregistration_reason == PERMANENT_TERMINATION) ||
                                 (_deregistration_reason == REMOVE_SCSCF)))
  {
    // Find information about the registration sets for the public
    // identities specified on the request.
    get_registration_sets();
  }
  else
  {
    // This is either an invalid deregistration reason.
    LOG_ERROR("Registration-Termination request received with invalid deregistration reason %d",
              _deregistration_reason);
    send_rta(DIAMETER_REQ_FAILURE);
    delete this;
  }
}

void RegistrationTerminationHandler::get_assoc_primary_public_ids_success(Cache::Request* request)
{
  // Get the default public identities returned by the cache.
  Cache::GetAssociatedPrimaryPublicIDs* get_associated_impus_result =
    (Cache::GetAssociatedPrimaryPublicIDs*)request;
  get_associated_impus_result->get_result(_impus);

  if (_impus.empty())
  {
    LOG_DEBUG("No registered IMPUs to deregister found");
    send_rta(DIAMETER_REQ_SUCCESS);
    delete this;
  }
  else
  {
    // We now have all the default public identities. Find their registration sets.
    // Remove any duplicates first. We do this by sorting the vector, using unique
    // to move the unique values to the front and erasing everything after the last
    // unique value.
    sort(_impus.begin(), _impus.end());
    _impus.erase(unique(_impus.begin(), _impus.end()), _impus.end());
    get_registration_sets();
  }
}

void RegistrationTerminationHandler::get_assoc_primary_public_ids_failure(Cache::Request* request,
                                                                          Cache::ResultCode error,
                                                                          std::string& text)
{
  LOG_DEBUG("Failed to get associated default public identities");
  send_rta(DIAMETER_REQ_FAILURE);
  delete this;
}

void RegistrationTerminationHandler::get_registration_sets()
{
  // This function issues a GetIMSSubscription cache request for a public identity
  // on the list of IMPUs and then removes that public identity from the list. It
  // should get called again after the cache response by the callback functions.
  // Once there are no public identities remaining, it deletes the registrations.
  if (!_impus.empty())
  {
    std::string impu = _impus.back();
    _impus.pop_back();
    LOG_DEBUG("Finding registration set for public identity %s", impu.c_str());
    Cache::Request* get_ims_sub = _cfg->cache->create_GetIMSSubscription(impu);
    CacheTransaction* tsx = new CacheTransaction(this);
    tsx->set_success_clbk(&RegistrationTerminationHandler::get_registration_set_success);
    tsx->set_failure_clbk(&RegistrationTerminationHandler::get_registration_set_failure);
    _cfg->cache->send(tsx, get_ims_sub);
  }
  else if (_registration_sets.empty())
  {
    LOG_DEBUG("No registered IMPUs to deregister found");
    send_rta(DIAMETER_REQ_SUCCESS);
    delete this;
  }
  else
  {
    // We now have all the registration sets, and we can delete the registrations.
    // First remove any duplicates in the list of _impis. We do this
    // by sorting the vector, using unique to move the unique values to the front
    // and erasing everything after the last unique value.
    sort(_impis.begin(), _impis.end());
    _impis.erase(unique(_impis.begin(), _impis.end()), _impis.end());

    delete_registrations();
  }
}

void RegistrationTerminationHandler::get_registration_set_success(Cache::Request* request)
{
  Cache::GetIMSSubscription* get_ims_sub_result = (Cache::GetIMSSubscription*)request;
  std::string ims_sub;
  int32_t temp;
  get_ims_sub_result->get_xml(ims_sub, temp);

  // Add the list of public identities in the IMS subscription to
  // the list of registration sets..
  std::vector<std::string> public_ids = XmlUtils::get_public_ids(ims_sub);
  if (!public_ids.empty())
  {
    _registration_sets.push_back(XmlUtils::get_public_ids(ims_sub));
  }

  if ((_deregistration_reason == SERVER_CHANGE) ||
      (_deregistration_reason == NEW_SERVER_ASSIGNED))
  {
    // GetIMSSubscription also returns a list of associated private
    // identities. Save these off.
    std::vector<std::string> associated_impis;
    get_ims_sub_result->get_associated_impis(associated_impis);
    std::string associated_impis_string = boost::algorithm::join(associated_impis, ", ");
    LOG_DEBUG("GetIMSSubscription returned associated identites: %s",
              associated_impis_string.c_str());
    _impis.insert(_impis.end(),
                  associated_impis.begin(),
                  associated_impis.end());
  }

  // Call back into get_registration_sets
  get_registration_sets();
}

void RegistrationTerminationHandler::get_registration_set_failure(Cache::Request* request,
                                                                  Cache::ResultCode error,
                                                                  std::string& text)
{
  LOG_DEBUG("Failed to get a registration set - report failure to HSS");
  send_rta(DIAMETER_REQ_FAILURE);
  delete this;
}

void RegistrationTerminationHandler::delete_registrations()
{
  // No real SAS implementation yet. TODO.
  SAS::TrailId fake_trail = 0;
  HTTPCode ret_code = 0;
  std::vector<std::string> empty_vector;
  std::vector<std::string> default_public_identities;

  // Extract the default public identities from the registration sets. These are the
  // first public identities in the sets.
  for (std::vector<std::vector<std::string>>::iterator i = _registration_sets.begin();
       i != _registration_sets.end();
       i++)
  {
    default_public_identities.push_back((*i)[0]);
  }

  // We need to notify sprout of the deregistrations. What we send to sprout depends
  // on the deregistration reason.
  switch (_deregistration_reason)
  {
  case PERMANENT_TERMINATION:
    ret_code = _cfg->sprout_conn->deregister_bindings(false,
                                                      default_public_identities,
                                                      _impis,
                                                      fake_trail);
    break;

  case REMOVE_SCSCF:
  case SERVER_CHANGE:
    ret_code = _cfg->sprout_conn->deregister_bindings(true,
                                                      default_public_identities,
                                                      empty_vector,
                                                      fake_trail);
    break;

  case NEW_SERVER_ASSIGNED:
    ret_code = _cfg->sprout_conn->deregister_bindings(false,
                                                      default_public_identities,
                                                      empty_vector,
                                                      fake_trail);
    break;

  default:
    // LCOV_EXCL_START - We can't get here because we've already filtered these out.
    LOG_ERROR("Unexpected deregistration reason %d on RTR", _deregistration_reason);
    break;
    // LCOV_EXCL_STOP
  }

  switch (ret_code)
  {
  case HTTP_OK:
    LOG_DEBUG("Send Registration-Termination answer indicating success");
    send_rta(DIAMETER_REQ_SUCCESS);
    break;

  case HTTP_BADMETHOD:
  case HTTP_BAD_RESULT:
  case HTTP_SERVER_ERROR:
    LOG_DEBUG("Send Registration-Termination answer indicating failure");
    send_rta(DIAMETER_REQ_FAILURE);
    break;

  default:
    LOG_ERROR("Unexpected HTTP return code, send Registration-Termination answer indicating failure");
    send_rta(DIAMETER_REQ_FAILURE);
    break;
  }

  // Remove the relevant registration information from Cassandra.
  dissociate_implicit_registration_sets();

  if ((_deregistration_reason == SERVER_CHANGE) ||
      (_deregistration_reason == NEW_SERVER_ASSIGNED))
  {
    LOG_DEBUG("Delete IMPI mappings");
    delete_impi_mappings();
  }

  delete this;
}

void RegistrationTerminationHandler::dissociate_implicit_registration_sets()
{
  // Dissociate the private identities from each registration set.
  for (std::vector<std::vector<std::string>>::iterator i = _registration_sets.begin();
       i != _registration_sets.end();
       i++)
  {
    Cache::Request* dissociate_reg_set =
      _cfg->cache->create_DissociateImplicitRegistrationSetFromImpi(*i, _impis, Cache::generate_timestamp());
    CacheTransaction* tsx = new CacheTransaction(this);
    _cfg->cache->send(tsx, dissociate_reg_set);
  }
}

void RegistrationTerminationHandler::delete_impi_mappings()
{
  // Delete rows from the IMPI table for all associated IMPIs.
  std::string _impis_string = boost::algorithm::join(_impis, ", ");
  LOG_DEBUG("Deleting IMPI mappings for the following IMPIs: %s",
            _impis_string.c_str());
  Cache::Request* delete_impis =
    _cfg->cache->create_DeleteIMPIMapping(_impis, Cache::generate_timestamp());
  CacheTransaction* tsx = new CacheTransaction(this);
  _cfg->cache->send(tsx, delete_impis);
}

void RegistrationTerminationHandler::send_rta(const std::string result_code)
{
  // Use our Cx layer to create a RTA object and add the correct AVPs. The RTA is
  // created from the RTR.
  Cx::RegistrationTerminationAnswer rta(_msg,
                                        _cfg->dict,
                                        result_code,
                                        _msg.auth_session_state(),
                                        _impis);

  // Send the RTA back to the HSS.
  LOG_INFO("Ready to send RTA");
  rta.send();
}

void PushProfileHandler::run()
{
  // Received a Push Profile Request. We may need to update a digest in the cache. We may
  // need to update an IMS subscription in the cache.
  Cx::PushProfileRequest ppr(_msg);
  _impi = ppr.impi();
  _digest_av = ppr.digest_auth_vector();
  ppr.user_data(_ims_subscription);

  // If we have a private ID and a digest specified on the PPR, update the digest for this impi
  // in the cache. If we have an IMS subscription, update the IMPU table for each public ID.
  // Otherwise just reply to the HSS.
  if ((!_impi.empty()) && (!_digest_av.ha1.empty()))
  {
    update_av();
  }
  else if (!_ims_subscription.empty())
  {
    update_ims_subscription();
  }
  else
  {
    send_ppa(DIAMETER_REQ_SUCCESS);
  }
}

void PushProfileHandler::update_av()
{
  LOG_INFO("Updating digest for private ID %s from PPR", _impi.c_str());
  Cache::Request* put_auth_vector = _cfg->cache->create_PutAuthVector(_impi,
                                                                      _digest_av,
                                                                      Cache::generate_timestamp(),
                                                                      _cfg->impu_cache_ttl);
  CacheTransaction* tsx = new CacheTransaction(this);
  tsx->set_success_clbk(&PushProfileHandler::update_av_success);
  tsx->set_failure_clbk(&PushProfileHandler::update_av_failure);
  _cfg->cache->send(tsx, put_auth_vector);
}

void PushProfileHandler::update_av_success(Cache::Request* request)
{
  // If we also need to update an IMS subscription, do that. Otherwise send a
  // successful response to the HSS.
  if (!_ims_subscription.empty())
  {
    update_ims_subscription();
  }
  else
  {
    send_ppa(DIAMETER_REQ_SUCCESS);
  }
}

void PushProfileHandler::update_av_failure(Cache::Request* request,
                                           Cache::ResultCode error,
                                           std::string& text)
{
  LOG_DEBUG("Failed to update AV for %s - report failure to HSS", _impi.c_str());
  send_ppa(DIAMETER_REQ_FAILURE);
}

void PushProfileHandler::update_ims_subscription()
{
  LOG_INFO("Updating IMS subscription from PPR");
  std::vector<std::string> impus = XmlUtils::get_public_ids(_ims_subscription);
  RegistrationState state = RegistrationState::UNCHANGED;
  Cache::Request* put_ims_subscription =
    _cfg->cache->create_PutIMSSubscription(impus,
                                           _ims_subscription,
                                           state,
                                           Cache::generate_timestamp(),
                                           (2 * _cfg->hss_reregistration_time));
  CacheTransaction* tsx = new CacheTransaction(this);
  tsx->set_success_clbk(&PushProfileHandler::update_ims_subscription_success);
  tsx->set_failure_clbk(&PushProfileHandler::update_ims_subscription_failure);
  _cfg->cache->send(tsx, put_ims_subscription);
}

void PushProfileHandler::update_ims_subscription_success(Cache::Request* request)
{
  // Send a successful response to the HSS.
  send_ppa(DIAMETER_REQ_SUCCESS);
}

void PushProfileHandler::update_ims_subscription_failure(Cache::Request* request,
                                                         Cache::ResultCode error,
                                                         std::string& text)
{
  LOG_DEBUG("Failed to update IMS subscription - report failure to HSS");
  send_ppa(DIAMETER_REQ_FAILURE);
}

void PushProfileHandler::send_ppa(const std::string result_code)
{
  // Use our Cx layer to create a PPA object and add the correct AVPs. The PPA is
  // created from the PPR.
  Cx::PushProfileAnswer ppa(_msg,
                            _cfg->dict,
                            result_code,
                            _msg.auth_session_state());

  // Send the PPA back to the HSS.
  LOG_INFO("Ready to send PPA");
  ppa.send();

  delete this;
}
