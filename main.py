import arp_poison
import http_handling
import subnet_info
import mdns_querying

def main():
    command = input("Enter Command:\n- Find Targets [F]\n- Attack Target [A]\n")
    if command == 'F':
        hostnames = subnet_info.get_subnet_hostnames()
        for hostname in hostnames:
            print(hostname)
    if command == 'A':
        target = input("Enter target: ")
        arp_poison.poison(target)
        http_handling.handle_http_get_request(target)


if __name__ == "__main__":
    main()
