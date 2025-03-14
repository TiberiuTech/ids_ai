from sqlalchemy import create_engine, Integer, String, DateTime, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from datetime import datetime
import warnings

# Suppress SQLAlchemy warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

class Base(DeclarativeBase):
    pass

class NetworkEvent(Base):
    __tablename__ = 'network_events'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    src_ip: Mapped[str] = mapped_column(String)
    dst_ip: Mapped[str] = mapped_column(String)
    is_anomaly: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)

class DatabaseManager:
    def __init__(self):
        self.engine = create_engine('sqlite:///network_events.db', echo=False)
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        
    def save_event(self, packet_info, is_anomaly, confidence):
        event = NetworkEvent(
            src_ip=packet_info['src_ip'],
            dst_ip=packet_info['dst_ip'],
            is_anomaly=int(is_anomaly),
            confidence=float(confidence)
        )
        self.session.add(event)
        self.session.commit()
