import logging
from pprint import pp
from typing import Iterable, Any, Iterator
from dataclasses import dataclass

from meraki import DashboardAPI

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

    @staticmethod
    def from_dict(ap_data: dict[str, Any]) -> 'BSSID':

        return AccessPoint(
            serial=ap_data['serial'],
            name=ap_data['name'],
            mac=ap_data['mac'],
            model=ap_data['model'],
            bssids={ bssid['bssid']: BSSID.from_dict(bssid) for bssid in ap_data.get('basicServiceSets', []) }
        )


class WirelessNetwork:

    def __init__(self, access_points: Iterable[AccessPoint] = None) -> None:
        self._nodes = dict()
        if access_points is not None:
            self.add_nodes(access_points)

    def __iter__(self) -> Iterator[tuple[str, AccessPoint]]:
        return iter(self._nodes.items())
            
    def add_node(self, access_point: AccessPoint) -> None:
        if not isinstance(access_point, AccessPoint):
            raise TypeError(f'expected AccessPoint node, instead received {type(access_point).__name__}')
        self._nodes[access_point.serial] = access_point
    
    def add_nodes(self, access_points: Iterable[AccessPoint]):
        for access_point in access_points:
            self.add_node(access_point)
    
    @staticmethod
    def from_raw_data(raw_data: Iterable[dict[str, Any]]) -> 'WirelessNetwork':
        access_points = ( AccessPoint.from_dict(access_point_data) for access_point_data in raw_data )
        return WirelessNetwork(access_points)


class CustomDashboardAPI(DashboardAPI):

    def get_access_points_details_by_network(self, net_id: str) -> dict[str, Any]:
        devices = self.networks.getNetworkDevices(net_id)
        for node in devices:
            serial = node['serial']
            node |= self.wireless.getDeviceWirelessStatus(serial) # merge dicts
        return devices


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    NETWORK_ID = 'N_662029145223478556'
    dashboard = CustomDashboardAPI(inherit_logging_config=True)
    
    ap_details_collection = dashboard.get_access_points_details_by_network(NETWORK_ID)
    for serial, ap in WirelessNetwork.from_raw_data(ap_details_collection):
        pp(ap)



