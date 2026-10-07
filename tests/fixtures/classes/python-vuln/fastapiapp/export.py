from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .db import get_db
from .models import Order

router = APIRouter()


@router.get("/export/orders")
def export_orders(db: Session = Depends(get_db)):
    return db.query(Order).all()
