/**
 * @file serverassignmenttype.h defines the ServerAssignmentType structure.
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

#ifndef SERVERASSIGNMENTTYPE_H__
#define SERVERASSIGNMENTTYPE_H__

struct ServerAssignmentType
{
public:
  enum Type
  {
    NO_ASSIGNMENT = 0,
    REGISTRATION = 1,
    RE_REGISTRATION = 2,
    UNREGISTERED_USER = 3,
    TIMEOUT_DEREGISTRATION = 4,
    USER_DEREGISTRATION = 5,
    TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME = 6, // Currently not used
    USER_DEREGISTRATION_STORE_SERVER_NAME = 7, // Currently not used
    ADMINISTRATIVE_DEREGISTRATION = 8,
    AUTHENTICATION_FAILURE = 9,
    AUTHENTICATION_TIMEOUT = 10
  };

  ServerAssignmentType(const bool& lookup, const Type& type, const bool& dereg) :
    _cache_lookup(lookup), _server_assignment_type(type), _deregistration(dereg)
  {}

  inline bool cache_lookup() const {return _cache_lookup;}
  inline Type type() const {return _server_assignment_type;}
  inline bool deregistration() const {return _deregistration;}

  inline void unregistered_user_default() {_server_assignment_type = UNREGISTERED_USER;}

private:
  bool _cache_lookup;
  Type _server_assignment_type;
  bool _deregistration;
};

#endif
