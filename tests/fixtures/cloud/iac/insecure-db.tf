resource "aws_db_instance" "bad" {
  storage_encrypted   = false
  publicly_accessible = true
  password            = "hunter2supersecret"
}
