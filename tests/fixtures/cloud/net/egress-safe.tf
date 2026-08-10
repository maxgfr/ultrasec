resource "aws_security_group_rule" "out" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.default.id
}

resource "google_compute_firewall" "out2" {
  direction     = "EGRESS"
  source_ranges = ["0.0.0.0/0"]
}
