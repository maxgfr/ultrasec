import { Controller, Get } from "@nestjs/common";
import type { Repository } from "typeorm";
import type { Order } from "./order.entity";

@Controller("export")
export class ExportController {
  constructor(private readonly orders: Repository<Order>) {}

  @Get("orders")
  all(): Promise<Order[]> {
    return this.orders.find();
  }
}
