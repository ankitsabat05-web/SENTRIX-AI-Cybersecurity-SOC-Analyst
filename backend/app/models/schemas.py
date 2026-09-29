from pydantic import BaseModel
from datetime import datetime
from typing import Optional

#---------------------------------------------
# Request Schema
#---------------------------------------------

class AlertRequest(BaseModel):
    source: str
    event_type: str
    description: str

#---------------------------------------------
# Response Schema
#---------------------------------------------

class AlertResponse(BaseModel):
    alert_id: str
    source: str
    event_type: str
    description: str
    timestamp: datetime

    status: str
    severity: str
    threat_category: str

    ai_analysis: Optional[str] = None
    recommended_action: Optional[str] = None

#---------------------------------------------
# Health Check Schema
#---------------------------------------------

class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: datetime
    