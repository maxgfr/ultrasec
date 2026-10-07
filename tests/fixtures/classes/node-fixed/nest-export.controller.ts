import { Controller, Get } from "@nestjs/common";
import type { Repository } from "typeorm";
import type { Order } from "./order.entity";

@Controller("export")
export class ExportController {
  constructor(private readonly orders: Repository<Order>) {}

  @Get("orders")
  page(): Promise<Order[]> {
    return this.orders.find({ take: 500, order: { id: "ASC" } });
  }
}
