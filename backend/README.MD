cd backend
docker compose up --build


#postgresql table
docker exec -it cyber-surakshya-db psql -U soc_user -d soc_db


| Command                      | Purpose              |
| ---------------------------- | -------------------- |
| `\dt`                        | List tables          |
| `\d alerts`                  | Show table structure |
| `SELECT * FROM alerts;`      | Show alert records   |
| `SELECT * FROM analyses;`    | Show analyses        |
| `SELECT * FROM blocked_ips;` | Show blocked IPs     |
| `SELECT * FROM agents;`      | Show agents          |
| `\q`                         | Exit PostgreSQL      |
