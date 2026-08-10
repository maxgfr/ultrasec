resource "aws_db_instance" "good" {
  storage_encrypted   = true
  publicly_accessible = false
  password            = var.db_password
}

resource "azurerm_sql_server" "good2" {
  administrator_login_password = "${var.admin_pw}"
  api_key                      = data.vault_generic_secret.k.data["key"]
}
