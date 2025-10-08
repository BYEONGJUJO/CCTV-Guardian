
from logging.handlers import TimedRotatingFileHandler
import logging
import json
import os
from datetime import datetime
from typing import Any, Dict


class JsonFormatter(logging.Formatter):
    """JSON Lines 포맷터"""
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
        }
        
        if hasattr(record, "extra_data"):
            log_entry.update(record.extra_data)
        
        return json.dumps(log_entry, ensure_ascii=False)


def create_logger(name: str, log_dir: str = "./data/logs", level: str = "INFO"):
    """로거 인스턴스 생성"""
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers.clear()
    
    handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, f"{name}.jsonl"),
        when="D",
        interval=1,
        backupCount=14,
        encoding="utf-8"
    )
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    
    return logger


class CCTVLogger:
    """CCTV Guardian 전용 로거"""
    
    def __init__(self, log_dir: str = "./data/logs", level: str = "INFO"):
        self.log_dir = log_dir
        self.event_logger = create_logger("events", log_dir, level)
        self.threat_logger = create_logger("threats", log_dir, level)
    
    def _mask_ip(self, ip: str) -> str:
        """IP 주소 마스킹"""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return "unknown"
    
    def log_network_event(self, event_type: str, src_ip: str, dst_ip: str, 
                         port: int, protocol: str, **kwargs):
        """네트워크 이벤트 로깅"""
        extra_data = {
            "category": "network",
            "event_type": event_type,
            "src_ip": self._mask_ip(src_ip),
            "dst_ip": self._mask_ip(dst_ip),
            "port": port,
            "protocol": protocol,
            **kwargs
        }
        
        record = self.event_logger.makeRecord(
            self.event_logger.name, logging.INFO, "", 0,
            f"NETWORK: {event_type}", (), None
        )
        record.extra_data = extra_data
        self.event_logger.handle(record)
    
    def log_api_request(self, method: str, endpoint: str, src_ip: str,
                       status_code: int, response_time_ms: float, **kwargs):
        """API 요청 로깅"""
        extra_data = {
            "category": "api",
            "method": method,
            "endpoint": endpoint,
            "src_ip": self._mask_ip(src_ip),
            "status_code": status_code,
            "response_time_ms": round(response_time_ms, 2),
            **kwargs
        }
        
        record = self.event_logger.makeRecord(
            self.event_logger.name, logging.INFO, "", 0,
            f"API: {method} {endpoint}", (), None
        )
        record.extra_data = extra_data
        self.event_logger.handle(record)
    
    def log_threat(self, category: str, threat: Dict[str, Any]):
        """위협 탐지 로깅"""
        threat_data = {"category": category, **threat}
        
        if "src_ip" in threat_data:
            threat_data["src_ip_masked"] = self._mask_ip(threat_data["src_ip"])
            del threat_data["src_ip"]
        
        record = self.threat_logger.makeRecord(
            self.threat_logger.name, logging.WARNING, "", 0,
            f"THREAT: {threat.get('threat_type', 'UNKNOWN')}", (), None
        )
        record.extra_data = threat_data
        self.threat_logger.handle(record)


if __name__ == "__main__":
    logger = CCTVLogger()
    
    # 테스트
    logger.log_network_event(
        event_type="connection",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.10",
        port=554,
        protocol="TCP"
    )
    
    logger.log_api_request(
        method="POST",
        endpoint="/api/login",
        src_ip="192.168.1.50",
        status_code=200,
        response_time_ms=45.3,
        username="admin"
    )
    
    logger.log_threat(
        category="network",
        threat={
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": "10.0.0.5",
            "ports_scanned": 15
        }
    )
    
    print("✅ 로그 파일 생성 완료: ./data/logs/")
    print("   - events.jsonl")
    print("   - threats.jsonl")
