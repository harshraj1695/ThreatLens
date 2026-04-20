from collections import defaultdict
from datetime import datetime
import threading


def current_bucket():
    return datetime.now().strftime("%H:%M")


class DashboardState:
    def __init__(self):
        self.data = self._empty_data()
        self.lock = threading.Lock()

    def _empty_data(self):
        return {
            "alerts": [],
            "total": 0,
            "src_ip_counts": defaultdict(int),
            "category_counts": defaultdict(int),
            "proto_counts": defaultdict(int),
            "severity_counts": defaultdict(int),
            "alerts_per_minute": [],
            "last_minute_bucket": None,
            "last_minute_count": 0,
        }

    def clear(self):
        with self.lock:
            self.data = self._empty_data()

    def update(self, alert):
        with self.lock:
            self.data["alerts"].insert(0, alert)
            if len(self.data["alerts"]) > 500:
                self.data["alerts"] = self.data["alerts"][:500]

            self.data["total"] += 1
            self.data["src_ip_counts"][alert["src"]] += 1
            self.data["category_counts"][alert["category"]] += 1
            self.data["proto_counts"][alert["proto"]] += 1
            self.data["severity_counts"][alert["severity"]] += 1

            now_min = current_bucket()
            if self.data["last_minute_bucket"] != now_min:
                if self.data["last_minute_bucket"] is not None:
                    self.data["alerts_per_minute"].append(
                        {
                            "time": self.data["last_minute_bucket"],
                            "count": self.data["last_minute_count"],
                        }
                    )
                    if len(self.data["alerts_per_minute"]) > 20:
                        self.data["alerts_per_minute"] = self.data["alerts_per_minute"][-20:]
                self.data["last_minute_bucket"] = now_min
                self.data["last_minute_count"] = 1
            else:
                self.data["last_minute_count"] += 1

    def recent_alerts(self, limit=100):
        with self.lock:
            return self.data["alerts"][:limit]

    def stats(self, interface, alert_file, rules_file):
        with self.lock:
            top_src = sorted(self.data["src_ip_counts"].items(), key=lambda item: item[1], reverse=True)[:10]
            top_cat = sorted(self.data["category_counts"].items(), key=lambda item: item[1], reverse=True)
            top_proto = sorted(self.data["proto_counts"].items(), key=lambda item: item[1], reverse=True)
            alerts_per_minute = list(self.data["alerts_per_minute"])
            if self.data["last_minute_bucket"] is not None:
                alerts_per_minute.append(
                    {
                        "time": self.data["last_minute_bucket"],
                        "count": self.data["last_minute_count"],
                    }
                )

            return {
                "total": self.data["total"],
                "unique_src": len(self.data["src_ip_counts"]),
                "top_src": [{"ip": key, "count": value} for key, value in top_src],
                "categories": [{"name": key, "count": value} for key, value in top_cat],
                "protocols": [{"name": key, "count": value} for key, value in top_proto],
                "severity": dict(self.data["severity_counts"]),
                "alerts_per_minute": alerts_per_minute[-20:],
                "meta": {
                    "interface": interface,
                    "alert_file": alert_file,
                    "rules_file": rules_file,
                },
            }
