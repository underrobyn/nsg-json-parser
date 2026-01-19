import enum
import logging
from csv import DictWriter
from datetime import datetime, timedelta
from json import load
from os import makedirs


TS_KEY = '%d-%H:%M:%S'

class MsgDir(enum.Enum):
    UP = 0
    DOWN = 1


class MsgType(enum.Enum):
    UNKNOWN = 0
    GSM = "gsm"
    WCDMA = "wcdma"
    LTE = "lte"
    NR = "nr"
    ESM = "esm"
    EMM = "emm"


class NSGLayer3Msg:
    category: MsgType
    detail: dict
    direction: MsgDir
    pcap: str
    timestamp: datetime
    title: str

    def __init__(self, packet: dict):
        self.category = MsgType[packet.get("Category", "unknown").upper()]
        self.direction = MsgDir[packet.get("Direction", "unknown").upper()]
        self.detail = packet.get("Detail", {})
        self.pcap = packet.get("PCAPPacket", "")
        self.timestamp = datetime.fromisoformat(packet.get("EquipmentTimestamp", packet.get("Timestamp", "")))
        self.title = packet.get("Title", "")


class NsgModemEvent:
    description: str
    timestamp: datetime
    title: str

    def __init__(self, event: dict):
        self.description = event.get("Description", "")
        self.timestamp = datetime.fromisoformat(event.get("Timestamp", event.get("EquipmentTimestamp", "")))
        self.title = event.get("Title", "")


class NSGJsonDump:
    raw_data: dict
    filename: str
    output_dir: str

    device: str
    start: datetime
    end: datetime
    rows: list[dict]
    packets: list[NSGLayer3Msg]
    events: list[NsgModemEvent]

    timestamp_location_map: dict

    def __init__(self, filename: str):
        self.filename = filename
        self.packets = []
        self.events = []

        self.timestamp_location_map = {}

        self.output_dir = f"output/{self.filename.split('/')[-1].split('.')[0]}"
        makedirs(self.output_dir, exist_ok=True)

    def read_file(self):
        self.raw_data = {}
        with open(self.filename) as f:
            self.raw_data = load(f)
        logging.info(f"{len(self.raw_data['data'])} log records found")

        self.device = self.raw_data["device"]
        self.start = datetime.fromisoformat(self.raw_data["starttime"])
        self.end = datetime.fromisoformat(self.raw_data["endtime"])

    def create_location_map(self):
        # Try and ensure that each second the log file was running that we have a location
        current_time = self.start.replace(microsecond=0)
        end_time = self.end.replace(microsecond=0)
        while current_time <= end_time:
            self.timestamp_location_map[current_time.strftime(TS_KEY)] = None
            current_time += timedelta(seconds=1)

    def parse(self):
        self.read_file()
        self.create_location_map()
        self.enumerate_data()

    def enumerate_data(self):
        for row in self.raw_data["data"]:
            # Get current timestamp from the row, skip if there is not one
            current_timestamp = row.get("Timestamp", row.get("EquipmentTimestamp", None))
            if not current_timestamp:
                logging.warning(f"No timestamp found in row: {row}")
                continue
            current_timestamp_std = datetime.fromisoformat(current_timestamp).strftime(TS_KEY)

            if current_timestamp_std not in self.timestamp_location_map:
                logging.warning(f"timestamp outside range of testing: {current_timestamp_std}")
                continue

            if "Location" in row:
                self.timestamp_location_map[current_timestamp_std] = clean_location(row["Location"])

            if "messages" in row:
                for message in row["messages"]:
                    self.packets.append(NSGLayer3Msg(message))

            if "events" in row:
                for event in row["events"]:
                    self.events.append(NsgModemEvent(event))

    def dump(self):
        self.dump_locations()
        self.dump_signalling()
        self.dump_events()

    def dump_locations(self):
        # Dump all coordinates
        with open(f"{self.output_dir}/coordinates.csv", "w") as f:
            writer = DictWriter(f, fieldnames=['timestamp', 'Latitude', 'Longitude', 'Accuracy', 'Speed'])
            writer.writeheader()
            for timestamp, location in self.timestamp_location_map.items():
                if not location: continue
                writer.writerow({
                    'timestamp': timestamp,
                    **location
                })

    def dump_signalling(self):
        # Dump all L3 messages
        with open(f"{self.output_dir}/signalling.csv", "w") as f:
            writer = DictWriter(f, fieldnames=['category', 'direction', 'detail', 'timestamp', 'title', 'latitude', 'longitude'])
            writer.writeheader()
            for packet in self.packets:
                location = self.timestamp_location_map[packet.timestamp.strftime(TS_KEY)] if packet.timestamp.strftime(TS_KEY) in self.timestamp_location_map else None
                if not location: location = {'Latitude': None, 'Longitude': None, 'Accuracy': None, 'Speed': None}
                writer.writerow({
                    'latitude': location.get('Latitude', None),
                    'longitude': location.get('Longitude', None),
                    'category': packet.category,
                    'direction': packet.direction,
                    #'detail': packet.detail,
                    'timestamp': packet.timestamp.strftime(TS_KEY),
                    'title': packet.title,
                })

    def dump_events(self):
        # Dump all modem events
        with open(f"{self.output_dir}/events.csv", "w") as f:
            writer = DictWriter(f, fieldnames=['description', 'timestamp', 'title', 'latitude', 'longitude'])
            writer.writeheader()
            for event in self.events:
                location = self.timestamp_location_map[event.timestamp.strftime(TS_KEY)] if event.timestamp.strftime(TS_KEY) in self.timestamp_location_map else None
                if not location: location = {'Latitude': None, 'Longitude': None, 'Accuracy': None, 'Speed': None}
                writer.writerow({
                    'latitude': location.get('Latitude', None),
                    'longitude': location.get('Longitude', None),
                    'description': event.description,
                    'timestamp': event.timestamp.strftime(TS_KEY),
                    'title': event.title,
                })


def clean_location(loc: dict):
    return {
        "Latitude": loc.get("Latitude", None),
        "Longitude": loc.get("Longitude", None),
        "Accuracy": round(loc.get("Accuracy", 0), 2),
        "Speed": round(loc.get("Speed", 0), 2)
    }
