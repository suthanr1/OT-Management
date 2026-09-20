# OT Management – Phase 2 Server Starter

Backend starter for the OT Management app.

## Stack
- Node.js + Express
- PostgreSQL
- JWT session (30 days)
- bcrypt password hashing
- Server-side employee access control
- Unique `(employee_id, ot_date)` rule
- 26th → 25th cycle
- Admin-controlled OT rate
- Employee OT delete
- Online API foundation

## Setup
1. Install Node.js and PostgreSQL.
2. Create a PostgreSQL database named `ot_management`.
3. Copy `.env.example` to `.env`.
4. Set `DATABASE_URL` and a strong `JWT_SECRET`.
5. Set `RUN_SCHEMA=true` for the first start.
6. Run:
   npm install
   npm start
7. After schema creation, `RUN_SCHEMA` can be changed to `false`.

The API currently does not serve the Phase 1 HTML itself. The next integration step is to connect the existing PWA UI to these endpoints and add offline sync using IndexedDB/service worker.

## Security
The server is the authority for employee access. Employee requests use the employee ID in the signed session, rather than accepting an arbitrary employee ID from the browser.
