#!/usr/bin/env python
""" PyBeaconValidator

A simple script to validate automatically if the Cisco Meraki access
points in your network are broadcasting the same capabilities as 
specified on Dashboard.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import argparse
from pprint import pp
from typing import Iterable, Any, Iterator
from dataclasses import dataclass

from meraki import DashboardAPI
from pyshark import FileCapture
from pyshark.capture.capture import TSharkCrashException


__author__ = "Gioacchino Castorio"
__contact__ = "gioacchino.castorio@gmail.com"
__copyright__ = "Copyright 2023, Gioacchino Castorio"
__date__ = "2023/07/14"
__deprecated__ = False
__license__ = "GPLv3"
__maintainer__ = "developer"
__version__ = "0.0.1"


logging.basicConfig(level=logging.ERROR)


@dataclass(frozen=True)
class BSSID:
    bssid: str
    ssid_name: str
    ssid_number: int
    band: str
    visible: bool
    broadcasting: bool

    @staticmethod
    def from_dict(bssid_data: dict[str, Any]) -> 'BSSID':
        return BSSID(
            bssid=bssid_data['bssid'],
            ssid_name=bssid_data['ssidName'],
            ssid_number=bssid_data['ssidNumber'],
            band=bssid_data['band'],
            visible=bssid_data['visible'],
            broadcasting=bssid_data['broadcasting']
        )


@dataclass(frozen=True)
class AccessPoint:
    serial: str
    name: str
    mac: str
    model: str
    bssids: dict[str, BSSID]
    tags: list[str]

    @staticmethod
    def from_dict(ap_data: dict[str, Any]) -> 'BSSID':

        return AccessPoint(
            serial=ap_data['serial'],
            name=ap_data['name'],
            mac=ap_data['mac'],
            model=ap_data['model'],
            bssids={ bssid['bssid']: BSSID.from_dict(bssid) for bssid in ap_data.get('basicServiceSets', []) },
            tags=ap_data['tags']
        )


@dataclass(frozen=True)
class SSIDConfig:
    name: str
    number: int
    is_enabled: bool
    auth_mode: str
    encryption_mode: str | None
    wpa_type: str | None
    minimum_bitrate: int
    is_visible: bool
    all_aps: bool
    availability_tags: list[str] | None = None

    @staticmethod
    def from_dict(ssid_data: dict[str, Any]) -> 'SSIDConfig':

        return SSIDConfig(
            number=ssid_data['number'],
            name=ssid_data['name'],
            is_enabled=ssid_data['enabled'],
            auth_mode=ssid_data['authMode'],
            encryption_mode=ssid_data.get('encryptionMode', None),
            wpa_type=ssid_data.get('wpaEncryptionMode', None),
            minimum_bitrate=ssid_data['minBitrate'],
            is_visible=ssid_data['visible'],
            all_aps=ssid_data['availableOnAllAps'],
            availability_tags=ssid_data['availabilityTags']
        )

class WirelessNetwork:

    def __init__(self,
        access_points: Iterable[AccessPoint] = None,
        ssids: list[SSIDConfig] = None) -> None:
        self._nodes = dict()
        self.ssids = ssids if ssids is not None else []
        if access_points is not None:
            self.add_nodes(access_points)

    @property
    def access_points(self) -> dict[str, AccessPoint]:
        return self._nodes

    @property
    def ssids(self) -> list[SSIDConfig]:
        return self._ssids

    @ssids.setter
    def ssids(self, configs: list[SSIDConfig]) -> None:
        if not isinstance(configs, list):
            raise TypeError(f'expected a list of SSIDConfig, got a {type(configs).__name__!r}')
        if len(configs) > 15:
            raise TypeError(f'Cisco Meraki APs broadcast max 15 SSIDs, given a {len(configs)}')
        if any(not isinstance(c, SSIDConfig) for c in configs):
            raise TypeError('expected a list of SSIDConfig')
        self._ssids = configs
        

    def __iter__(self) -> Iterator[tuple[str, AccessPoint]]:
        return iter(self._nodes.items())
            
    def add_node(self, access_point: AccessPoint) -> None:
        if not isinstance(access_point, AccessPoint):
            raise TypeError(f'expected AccessPoint node, instead received {type(access_point).__name__}')
        self._nodes[access_point.serial] = access_point
    
    def add_nodes(self, access_points: Iterable[AccessPoint]):
        for access_point in access_points:
            self.add_node(access_point)

    def get_bssid_lookup_table(self) -> dict[str, AccessPoint]:
        result = dict()
        for ap in self._nodes.values():
            result |= {bssid : ap for bssid in ap.bssids.keys()}
        return result
    
    @staticmethod
    def from_raw_data(ap_raw_data: Iterable[dict[str, Any]],
                      ssid_raw_data: Iterable[dict[str, Any]] = None) -> 'WirelessNetwork':
        access_points = [ AccessPoint.from_dict(access_point_data) for access_point_data in ap_raw_data ]
        ssid_config = [ SSIDConfig.from_dict(ssid_data) for ssid_data in ssid_raw_data ]
        return WirelessNetwork(access_points, ssid_config)


class CustomDashboardAPI(DashboardAPI):

    def get_access_points_details_by_network(self, net_id: str) -> dict[str, Any]:
        devices = self.networks.getNetworkDevices(net_id)
        for node in devices:
            serial = node['serial']
            node |= self.wireless.getDeviceWirelessStatus(serial) # merge dicts
        return devices

    def get_ssid_information_by_network(self, net_id: str) -> dict[str, Any]:
        return self.wireless.getNetworkWirelessSsids(net_id)

    def get_wireless_network(self, net_id: str) -> WirelessNetwork:
        ap_details_collection = self.get_access_points_details_by_network(net_id)
        ssid_details = self.get_ssid_information_by_network(net_id)
        return WirelessNetwork.from_raw_data(ap_details_collection, ssid_details)


def _filter_wlan_pcap_frames(capture):
    try:
        for frame in capture:
            if not hasattr(frame, 'wlan'):
                continue
            yield frame
    except TSharkCrashException as e:
        # this exception happens only if the capture was cut short
        print('frame was cut off mid capture -- ignoring')


@dataclass(frozen=True)
class BeaconFrame:
    ta_bssid: str
    channel: int


def get_beacon_information_from_pcap(capture_path: str) -> dict[str,list[BeaconFrame]]:
    BEACON_TSHARK_FITLER = 'wlan.fc.type_subtype == 0x8'
    capture = FileCapture(capture_path, display_filter=BEACON_TSHARK_FITLER, use_json=True, include_raw=False)
    beacons = dict()
    for frame in _filter_wlan_pcap_frames(capture):
        beacon_frame = BeaconFrame(
            ta_bssid=frame.wlan.ta,
            channel=frame.wlan_radio.channel
        )
        beacons.setdefault(beacon_frame.ta_bssid, []).append(beacon_frame)
    return beacons


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
                    prog='PyBeaconValidator',
                    description='''A simple script to validate automatically if the Cisco Meraki access
                                points in your network are broadcasting the same capabilities as
                                specified on Dashboard''',
                    epilog='''This software is distributed as GNU GPLv3 free software.\n
                            Copyright 2023, Gioacchino Castorio''')
    parser.add_argument('packet_capture_file',
                        metavar='PCAP', 
                        type=str,
                        help='path to the .pcap/.pcapng with the beacon frames to validate')
    parser.add_argument('--network', '-n',
                        dest='network_id',
                        required=True,
                        help='ID of the Cisco Meraki network')
    args = parser.parse_args()


    dashboard = CustomDashboardAPI(inherit_logging_config=True)
    network = dashboard.get_wireless_network(args.network_id)
    bssid_table = network.get_bssid_lookup_table()


    seen_beacons = get_beacon_information_from_pcap(args.packet_capture_file)
    pp(seen_beacons)

    # tshark_filter = 'wlan.fc.type_subtype == 0x8'
    # capture = FileCapture(args.packet_capture_file, display_filter=tshark_filter, use_json=True, include_raw=False)

    # knwon_beacons = list()
    # seen_bssid = set()
    # for frame in _filter_wlan_pcap_frames(capture):
    #     transmitted_addr = frame.wlan.ta
    #     channel = frame.wlan_radio.channel
    #     if transmitted_addr not in seen_bssid and  transmitted_addr in bssid_table:
    #         frame_data = dict()
    #         ap = bssid_table[transmitted_addr]
    #         frame_data['bssid'] = transmitted_addr
    #         # frame_data['ssid'] = ap.bssids[transmitted_addr].ssid_name
    #         frame_data['ap_sn'] = ap.serial
    #         # frame_data['ap_name'] = ap.bssids[transmitted_addr].ssid_name
    #         # frame_data['ap_model'] = ap.model
    #         # frame_data['band'] = ap.bssids[transmitted_addr].band
    #         frame_data['channel'] = channel
    #         knwon_beacons.append(frame_data)
    #         seen_bssid.add(transmitted_addr)
    
    # pp(knwon_beacons)
    # pp(network.access_points)


