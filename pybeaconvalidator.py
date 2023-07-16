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
from datetime import datetime

from meraki import DashboardAPI
from pypacker import ppcap
from pypacker.layer12 import radiotap, ieee80211


__author__ = "Gioacchino Castorio"
__contact__ = "gioacchino.castorio@gmail.com"
__copyright__ = "Copyright 2023, Gioacchino Castorio"
__date__ = "2023/07/14"
__deprecated__ = False
__license__ = "GPLv3"
__maintainer__ = "developer"
__version__ = "0.0.1"


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


@dataclass(frozen=True)
class BeaconFrame:
    timestamp: int
    ta_bssid: str
    channel: int
    ssid: str
    supported_bitrates: list[int]


def _process_pypacker_frame_headers(radiotap_header: radiotap.Radiotap,
                           dot11_header: ieee80211.IEEE80211,
                           beacon_header: ieee80211.IEEE80211.Beacon,
                           epoch_nsec_ts: int = 0) -> BeaconFrame:

    channel_freq_mhz, _ = radiotap.get_channelinfo(radiotap_header.channel)
    channel_number = radiotap.freq_to_channel(channel_freq_mhz * 1e6)

    # supported bitrates
    supported_bitrates = []
    for b in beacon_header.params[1].body_bytes:

        # check if the bitrate value refers to a BASIC bitrate by checking the
        # first bit of the octect e.g. 1000 0000 --> Basic Bitrate
        is_mandatory = bool(b >> 7)

        # compute bitrate in Mbps by multiplying octect
        # remove if 1st bit in case of mandatory bitrate
        # bitrate = (octect * 500 kbps) // 1000
        bitrate = ((b - (1 << 7)) if is_mandatory else b) // 2
        supported_bitrates.append((is_mandatory, bitrate,))

    return BeaconFrame(
        timestamp=epoch_nsec_ts,
        ta_bssid=beacon_header.src_s.casefold(),
        channel=channel_number,
        ssid=beacon_header.essid.decode(),
        supported_bitrates=supported_bitrates
    )
  

def get_beacon_information_from_pcap(capture_file_path: str) -> Iterable[BeaconFrame]:
    with ppcap.Reader(capture_file_path) as capture_reader:
        beacons = list()
        for ts_ns, buf in capture_reader:
            frame = radiotap.Radiotap(buf)
            radiotap_header, dot11_header, beacon_payload = frame[None, ieee80211.IEEE80211, ieee80211.IEEE80211.Beacon]
            if beacon_payload is None:
                continue
            beacon_frame = _process_pypacker_frame_headers(radiotap_header, dot11_header, beacon_payload, ts_ns)
            beacons.append(beacon_frame)
    return beacons


@dataclass(frozen=True)
class StatusPair:
    name: str
    expected: Any
    actual: Any

    @property
    def are_matching(self) -> bool:
        return self.expected == self.actual


def _get_compare_fields(access_point: AccessPoint, ssid_config: SSIDConfig, frame: BeaconFrame) -> set[StatusPair]:
    field_set = set()
    field_set.add(StatusPair('ssid name', expected=ssid_config.name, actual=frame.ssid))
    field_set.add(StatusPair('minimum bitrate', ssid_config.minimum_bitrate, frame.supported_bitrates[0][1]))
    return field_set


def compare(network: WirelessNetwork, beacons: Iterable[BeaconFrame]) -> Iterable[tuple[int, str, str, set[StatusPair]]]:
    bssid_table = network.get_bssid_lookup_table()
    result = list()
    for bc in beacons:
        ap = bssid_table.get(bc.ta_bssid, None)
        if ap is None:
            result.append((bc.timestamp, bc.ta_bssid, None, set(),))
        else:
            ssid_number = ap.bssids[bc.ta_bssid].ssid_number
            ssid_cfg = network.ssids[ssid_number]
            field_set = _get_compare_fields(ap, ssid_cfg, bc)
            result.append((bc.timestamp, bc.ta_bssid, ap.serial, field_set,))
    return result


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
    parser.add_argument('--debug-no-dash',
                        dest='debug_no_dashboard',
                        action='store_false',
                        help='if enabled, the program does not connect to the Cisco Meraki API')
    args = parser.parse_args()


    # setup
    logging.basicConfig(level=logging.WARNING)
    dashboard = CustomDashboardAPI(inherit_logging_config=True)

    print('requesting API data')
    wireless_network = dashboard.get_wireless_network(args.network_id)

    print('START reading beacond')
    seen_beacons = get_beacon_information_from_pcap(args.packet_capture_file)
    print('FINISH reading beacond')

    comparisons = compare(wireless_network, seen_beacons)
    
    for c in comparisons:
        ts = c[0]
        bssid = c[1]
        serial = c[2]
        pairs = c[3]
        if serial is None:
            logging.info('unknown AP (BSSID %r) seen beaconing at %r', bssid, ts)
            continue
        for stat in pairs:
            if stat.are_matching:
                logging.info('ts %s, sn %r, bssid %r, matching %r (seen: %r)', ts, serial, bssid, stat.name, stat.actual)
            else:
                logging.warning('ts %s, sn %r, bssid %r, mismatch %r (expected: %r, seen: %r)', ts, serial, bssid, stat.name, stat.expected, stat.actual)

