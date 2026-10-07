from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .db import get_db
from .models import Order

router = APIRouter()


@router.get("/export/orders")
def export_orders(offset: int = 0, db: Session = Depends(get_db)):
    return db.query(Order).order_by(Order.id).offset(offset).limit(500).all()
