#!/usr/bin/env python3

import argparse
import json
from collections import defaultdict
import hashlib

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.layers.eap import EAPOL, EAP

CIPHER_SUITES = {
    0: "Use group cipher suite",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256"
}

AKM_SUITES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SUITE-B",
    12: "802.1X-SUITE-B-192",
    18: "OWE"
}

EAP_METHODS = {
    4: 'MD5-Challenge',
    13: 'TLS',
    21: 'TTLS',
    25: 'PEAP',
    43: 'FAST'
}


# parse the RSN information element bytes
def parse_rsn_ie(rsn_data):
    if len(rsn_data) < 8:
        return None
    
    result = {}
    offset = 0
    
    # version
    version = int.from_bytes(rsn_data[offset:offset+2], 'little')
    offset += 2
    
    # group cipher suite
    if len(rsn_data) >= offset + 4:
        group_cipher = rsn_data[offset+3]
        result['GroupCipher'] = CIPHER_SUITES.get(group_cipher, f"Unknown({group_cipher})")
        offset += 4
    
    # pairwise cipher suites
    if len(rsn_data) >= offset + 2:
        pairwise_count = int.from_bytes(rsn_data[offset:offset+2], 'little')
        offset += 2
        result['PairwiseCiphers'] = []
        
        for i in range(pairwise_count):
            if len(rsn_data) >= offset + 4:
                cipher = rsn_data[offset+3]
                result['PairwiseCiphers'].append(
                    CIPHER_SUITES.get(cipher, f"Unknown({cipher})")
                )
                offset += 4
    
    # akm suites
    if len(rsn_data) >= offset + 2:
        akm_count = int.from_bytes(rsn_data[offset:offset+2], 'little')
        offset += 2
        result['AKM'] = []
        
        for i in range(akm_count):
            if len(rsn_data) >= offset + 4:
                akm = rsn_data[offset+3]
                result['AKM'].append(
                    AKM_SUITES.get(akm, f"Unknown({akm})")
                )
                offset += 4
    
    # rsn capabilities 
    if len(rsn_data) >= offset + 2:
        capabilities = int.from_bytes(rsn_data[offset:offset+2], 'little')
        # bit 7 is MFPC, bit 6 is MFPR
        result['MFPC'] = bool(capabilities & 0x80)
        result['MFPR'] = bool(capabilities & 0x40)
        offset += 2
    
    return result


def extract_rsn_info(pcap_file):
    networks = {}
    packets = rdpcap(pcap_file)
    
    for pkt in packets:
        # beacons and probe responses
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                bssid = pkt[Dot11].addr3
                
                # SSID
                ssid = ""
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        elt = elt.payload.getlayer(Dot11Elt)
                
                channel = 0
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 3: 
                            channel = elt.info[0]
                            break
                        elt = elt.payload.getlayer(Dot11Elt)
                
                # RSN IE 
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 48: 
                            rsn_info = parse_rsn_ie(bytes(elt.info))
                            if rsn_info and bssid not in networks:
                                networks[bssid] = {
                                    'BSSID': bssid,
                                    'SSID': ssid,
                                    'Channel': channel,
                                    'PairwiseCiphers': rsn_info.get('PairwiseCiphers', []),
                                    'GroupCipher': rsn_info.get('GroupCipher', 'Unknown'),
                                    'AKM': rsn_info.get('AKM', []),
                                    'MFPC': rsn_info.get('MFPC', False),
                                    'MFPR': rsn_info.get('MFPR', False)
                                }
                        elt = elt.payload.getlayer(Dot11Elt)
            except Exception as e:
                # skipping malformed ones
                continue
    
    return list(networks.values())


def summarize_eap_flows(pcap_file):
    print(f"summarizing eap flows from {pcap_file}...")
    
    clients = defaultdict(lambda: {
        'ClientMAC': '',
        'SSID': '',
        'Timestamps': [],
        'EAPIdentity': None,
        'EAPMethod': None,
        'OuterTLS': False,
        'FourWayHandshakeObserved': False,
        'EAPOL_Messages': []
    })
    
    packets = rdpcap(pcap_file)
    assocs = {}  
    
    for pkt in packets:
        try:
            timestamp = float(pkt.time)
            
            # association req,res has the SSID
            if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11AssoResp):
                if pkt.haslayer(Dot11):
                    client_mac = pkt[Dot11].addr2
                    bssid = pkt[Dot11].addr1
                    
                    if pkt.haslayer(Dot11Elt):
                        elt = pkt[Dot11Elt]
                        while elt:
                            if elt.ID == 0:
                                ssid = elt.info.decode('utf-8', errors='ignore')
                                assocs[client_mac] = ssid
                                break
                            elt = elt.payload.getlayer(Dot11Elt)
            
            # eapol packets
            if pkt.haslayer(EAPOL):
                if pkt.haslayer(Dot11):
                    client_mac = pkt[Dot11].addr2
                    
                    if client_mac not in clients:
                        clients[client_mac]['ClientMAC'] = client_mac
                        clients[client_mac]['SSID'] = assocs.get(client_mac, 'Unknown')
                    
                    clients[client_mac]['Timestamps'].append(f"{timestamp:.2f}")
                    
                    eapol = pkt[EAPOL]
                    clients[client_mac]['EAPOL_Messages'].append(eapol.type)
                    
                    if eapol.type == 3:
                        clients[client_mac]['FourWayHandshakeObserved'] = True
                    
                    if pkt.haslayer(EAP):
                        eap = pkt[EAP]
                        
                        if eap.type == 1 and eap.code == 2: 
                            try:
                                identity = eap.identity.decode('utf-8', errors='ignore')
                                clients[client_mac]['EAPIdentity'] = identity
                            except:
                                pass
                        
                        if eap.type in EAP_METHODS:
                            clients[client_mac]['EAPMethod'] = EAP_METHODS[eap.type]
                            
                            if eap.type in [13, 21, 25]:
                                clients[client_mac]['OuterTLS'] = True
            
        except Exception as e:
            continue
    
    for client_data in clients.values():
        client_data['Timestamps'] = sorted(list(set(client_data['Timestamps']))[:10])
        del client_data['EAPOL_Messages']
    
    return list(clients.values())


def print_eap_summary(clients):
    print("\n")
    print("EAP/EAPOL Flow Summary")
    
    for client in clients:
        print(f"\nClient {client['ClientMAC']} associated to {client['SSID']}:")
        
        if client['EAPIdentity']:
            print(f"  - EAP identity={client['EAPIdentity']}")
        else:
            print(f"  - EAP identity=Not observed")
        
        if client['EAPMethod']:
            tls_info = " (with outer TLS)" if client['OuterTLS'] else ""
            print(f"  - EAP method={client['EAPMethod']}{tls_info}")
        else:
            print(f"  - EAP method=Not detected")
        
        if client['FourWayHandshakeObserved']:
            print(f"  - 4-way handshake was seen")
        else:
            print(f"  - 4-way handshake not observed")
            
    print("\n")


def get_anonymous_mac(org_mac, mac_map):
    if org_mac not in mac_map:        
        hash_bytes = hashlib.sha256(org_mac.encode()).digest()[:6]
        anon_mac = ':'.join([f'{b:02x}' for b in hash_bytes])
        mac_map[org_mac] = anon_mac
    return mac_map[org_mac]


def get_anonymous_identity(org_identitiy, identity_map, counter):
    if org_identitiy not in identity_map:
        identity_map[org_identitiy] = f"user{counter[0]}"
        counter[0] += 1
    return identity_map[org_identitiy]


def anonymize_pcap(input_file, output_file, mapping_file):
    print(f"Anonymizing {input_file}")
    
    mac_map = {}
    identity_map = {}
    id_counter = [1]
    
    packets = rdpcap(input_file)
    anonymized_packets = []
    
    for pkt in packets:
        new_pkt = pkt.copy()
        
        # replacing all MAC addresses
        if new_pkt.haslayer(Dot11):
            dot11 = new_pkt[Dot11]
            if dot11.addr1:
                dot11.addr1 = get_anonymous_mac(dot11.addr1, mac_map)
            if dot11.addr2:
                dot11.addr2 = get_anonymous_mac(dot11.addr2, mac_map)
            if dot11.addr3:
                dot11.addr3 = get_anonymous_mac(dot11.addr3, mac_map)
            if hasattr(dot11, 'addr4') and dot11.addr4:
                dot11.addr4 = get_anonymous_mac(dot11.addr4, mac_map)
        
        # replacing all EAP identities
        if new_pkt.haslayer(EAP):
            eap = new_pkt[EAP]
            if eap.type == 1 and hasattr(eap, 'identity'):
                try:
                    org_identitiy = eap.identity.decode('utf-8', errors='ignore')
                    anon_identity = get_anonymous_identity(org_identitiy, identity_map, id_counter)
                    eap.identity = anon_identity.encode('utf-8')
                except:
                    pass
        
        anonymized_packets.append(new_pkt)
    
    # write output pcap
    wrpcap(output_file, anonymized_packets)
    
    mapping = {
        'MAC_mappings': [
            {'original': orig, 'anonymized': anon}
            for orig, anon in mac_map.items()
        ],
        'identity_mappings': [
            {'original': orig, 'anonymized': anon}
            for orig, anon in identity_map.items()
        ]
    }
    
    with open(mapping_file, 'w') as f:
        json.dump(mapping, f, indent=2)
    
    print(f"Anonymized pcap written to: {output_file}. Mapping file written to: {mapping_file}")
    
    return mapping


def main():
    parser = argparse.ArgumentParser(description='WNS Auditing Tool')
    
    parser.add_argument('--rsn-extract', metavar='PCAP', help='Extract RSN information')
    parser.add_argument('--eap-summary', metavar='PCAP', help='Summarize EAP/EAPOL flows')
    parser.add_argument('--anonymize', metavar='PCAP', help='Anonymize pcap file')
    parser.add_argument('--mapping', help='Mapping file for anonymization')
    parser.add_argument('--output', help='Output file path')

    args = parser.parse_args()
        
    if args.rsn_extract:
        rsn_data = extract_rsn_info(args.rsn_extract)
        output_file = args.output or 'rsn_output.json'    
    
        with open(output_file, 'w') as f:
            json.dump(rsn_data, f, indent=2)
        
        print(f"output written to: {output_file}")
    
    elif args.eap_summary:
        eap_data = summarize_eap_flows(args.eap_summary)
        output_file = args.output or 'eap_output.json'
        
        with open(output_file, 'w') as f:
            json.dump(eap_data, f, indent=2)
        
        print(f"output written to: {output_file}")
        print_eap_summary(eap_data)
    
    elif args.anonymize:
        mapping_file = args.mapping or 'mapping.json'
        output_file = args.output or 'anonymized.pcap'
        anonymize_pcap(args.anonymize, output_file, mapping_file)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()