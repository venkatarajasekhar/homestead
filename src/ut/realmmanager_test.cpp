/**
 * @file realmmanager_test.cpp UT for Homestead Realm Manager module.
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

#include "realmmanager.h"
#include "mockdiameterstack.hpp"
#include "mockdiameterresolver.hpp"

using ::testing::SetArgReferee;
using ::testing::_;
using ::testing::Return;

/// Fixture for RealmmanagerTest.
class RealmmanagerTest : public testing::Test
{
public:
  static const std::string DIAMETER_REALM;
  static const std::string DIAMETER_HOSTNAME;

  static MockDiameterStack* _mock_stack;
  static MockDiameterResolver* _mock_resolver;

  static void SetUpTestCase()
  {
    _mock_stack = new MockDiameterStack();
    _mock_resolver = new MockDiameterResolver();
  }

  static void TearDownTestCase()
  {
    delete _mock_stack; _mock_stack = NULL;
    delete _mock_resolver; _mock_resolver = NULL;
  }

  RealmmanagerTest() {}
  ~RealmmanagerTest() {}

  void set_all_peers_connected(RealmManager* realm_manager)
  {
    for (std::vector<Diameter::Peer*>::iterator ii = realm_manager->_peers.begin();
         ii != realm_manager->_peers.end();
         ii++)
    {
      realm_manager->connection_succeeded(*ii);
      (*ii)->_connected = true;
    }
  }
};

const std::string RealmmanagerTest::DIAMETER_REALM = "hss.example.com";
const std::string RealmmanagerTest::DIAMETER_HOSTNAME = "hss1.example.com";

MockDiameterStack* RealmmanagerTest::_mock_stack = NULL;
MockDiameterResolver* RealmmanagerTest::_mock_resolver = NULL;

//
// ip_addr_to_arpa Tests
//

TEST_F(RealmmanagerTest, IPv4HostTest)
{
  IP46Address ip_addr;
  ip_addr.af = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &ip_addr.addr.ipv4);
  std::string expected_host = "127.0.0.1";
  std::string host = Utils::ip_addr_to_arpa(ip_addr);
  EXPECT_EQ(expected_host, host);
}

TEST_F(RealmmanagerTest, IPv6HostTest)
{
  IP46Address ip_addr;
  ip_addr.af = AF_INET6;
  inet_pton(AF_INET6, "2001:db8::1", &ip_addr.addr.ipv6);
  std::string expected_host = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
  std::string host = Utils::ip_addr_to_arpa(ip_addr);
  EXPECT_EQ(expected_host, host);
}

TEST_F(RealmmanagerTest, IPv6HostTestLeading0s)
{
  IP46Address ip_addr;
  ip_addr.af = AF_INET6;
  inet_pton(AF_INET6, "::db6:1", &ip_addr.addr.ipv6);
  std::string expected_host = "1.0.0.0.6.b.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
  std::string host = Utils::ip_addr_to_arpa(ip_addr);
  EXPECT_EQ(expected_host, host);
}

TEST_F(RealmmanagerTest, IPv6HostTestTrailing0s)
{
  IP46Address ip_addr;
  ip_addr.af = AF_INET6;
  inet_pton(AF_INET6, "2001:db8::", &ip_addr.addr.ipv6);
  std::string expected_host = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
  std::string host = Utils::ip_addr_to_arpa(ip_addr);
  EXPECT_EQ(expected_host, host);
}

// This tests that we can create and destroy a RealmManager object.
TEST_F(RealmmanagerTest, CreateDestroy)
{
  AddrInfo peer;
  peer.address.af = AF_INET;
  inet_pton(AF_INET, "1.1.1.1", &peer.address.addr.ipv4);
  std::vector<AddrInfo> targets;

  RealmManager* realm_manager = new RealmManager(_mock_stack,
                                                 DIAMETER_REALM,
                                                 DIAMETER_HOSTNAME,
                                                 2,
                                                 _mock_resolver);

  targets.push_back(peer);
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(15)));
  EXPECT_CALL(*_mock_stack, add(_))
    .Times(1)
    .WillRepeatedly(Return(true));
  EXPECT_CALL(*_mock_stack, register_peer_hook_hdlr())
    .Times(1);
  realm_manager->start();

  // We have to sleep here to ensure that the main thread has been
  // created properly before we try and join to it during shutdown.
  sleep(1);

  EXPECT_CALL(*_mock_stack, remove(_))
    .Times(1);
  EXPECT_CALL(*_mock_stack, unregister_peer_hook_hdlr())
    .Times(1);
  realm_manager->stop();

  delete realm_manager;
}

// This tests that the RealmManager's manage_connections function
// behaves correctly when the DiameterResolver returns various
// combinations of peers.
TEST_F(RealmmanagerTest, ManageConnections)
{
  // Set up some AddrInfo structures for the diameter resolver
  // to return.
  AddrInfo peer1;
  peer1.transport = IPPROTO_TCP;
  peer1.port = 3868;
  peer1.address.af = AF_INET;
  inet_pton(AF_INET, "1.1.1.1", &peer1.address.addr.ipv4);
  AddrInfo peer2;
  peer2.transport = IPPROTO_TCP;
  peer2.port = 3868;
  peer2.address.af = AF_INET;
  inet_pton(AF_INET, "2.2.2.2", &peer2.address.addr.ipv4);
  AddrInfo peer3;
  peer3.transport = IPPROTO_TCP;
  peer3.port = 3868;
  peer3.address.af = AF_INET;
  inet_pton(AF_INET, "3.3.3.3", &peer3.address.addr.ipv4);
  std::vector<AddrInfo> targets;
  int ttl;

  // Create a RealmManager.
  RealmManager* realm_manager = new RealmManager(_mock_stack,
                                                 DIAMETER_REALM,
                                                 DIAMETER_HOSTNAME,
                                                 2,
                                                 _mock_resolver);

  // First run through. The diameter resolver returns two peers. We
  // expect to try and connect to them.
  targets.push_back(peer1);
  targets.push_back(peer2);
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(15)));
  EXPECT_CALL(*_mock_stack, add(_))
    .Times(2)
    .WillRepeatedly(Return(true));

  realm_manager->manage_connections(ttl);
  EXPECT_EQ(15, ttl);

  // The connection to peer1 fails. Set the connected flag on the
  // remaining peers. This should just be peer2.
  realm_manager->connection_failed(realm_manager->_peers.front());
  set_all_peers_connected(realm_manager);

  // The diameter resolver returns the peer we're already connected to
  // and a new peer. We expect to try and connect to the new peer.
  targets.clear();
  targets.push_back(peer2);
  targets.push_back(peer3);
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(10)));
  EXPECT_CALL(*_mock_stack, add(_))
    .Times(1)
    .WillOnce(Return(true));

  realm_manager->manage_connections(ttl);
  EXPECT_EQ(10, ttl);

  // Set the connected flag on the new peer.
  set_all_peers_connected(realm_manager);

  // The diameter resolver returns just one peer. We expect to tear down
  // one of the connections.
  targets.clear();
  targets.push_back(peer2);
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(15)));
  EXPECT_CALL(*_mock_stack, remove(_))
    .Times(1);

  realm_manager->manage_connections(ttl);

  // The diameter resolver returns two peers again. We expect to try and
  // reconnect to peer3. However, freeDiameter says we're already connected
  // to peer3, so it doesn't get added to the list of _peers.
  targets.clear();
  targets.push_back(peer2);
  targets.push_back(peer3);
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(15)));
  EXPECT_CALL(*_mock_stack, add(_))
    .Times(1)
    .WillOnce(Return(false));

  realm_manager->manage_connections(ttl);

  // The diameter resolver returns no peers. We expect to tear down the one
  // connection (to peer2) that we have up.
  targets.clear();
  EXPECT_CALL(*_mock_resolver, resolve(DIAMETER_REALM, DIAMETER_HOSTNAME, 2, _, _))
    .WillOnce(DoAll(SetArgReferee<3>(targets), SetArgReferee<4>(15)));
  EXPECT_CALL(*_mock_stack, remove(_))
    .Times(1);

  realm_manager->manage_connections(ttl);

  delete realm_manager;
}
