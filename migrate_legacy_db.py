"""Migrate the bundled legacy FastAPI SQLite data into Flask's inventory.db.

Run once from the project directory:
    python migrate_legacy_db.py

The script is intentionally separate from normal application startup so a
customer can choose when to import legacy data.
"""
import sqlite3
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "fastapi_app" / "app.db"
TARGET = ROOT / "inventory.db"

if not SOURCE.exists():
    raise SystemExit(f"Legacy database not found: {SOURCE}")
if TARGET.exists():
    raise SystemExit(f"Target database already exists: {TARGET}\nBack it up/remove it before running this migration again.")

print(f"Migrating {SOURCE} -> {TARGET}")
# This utility mirrors the same schema/data transformation used to create the
# packaged migrated database. It imports only data structures that can be
# represented safely by the current Flask IMS schema.

# To keep this standalone and dependency-free, create the new schema by
# importing the current app when dependencies are installed.
try:
    import app as ims_app
except Exception as exc:
    raise SystemExit("Install requirements.txt first, then run this script.\n" + str(exc))

with ims_app.app.app_context():
    ims_app.db.create_all()
    db = ims_app.db
    User = ims_app.User; Product = ims_app.Product; Sale = ims_app.Sale; SaleItem = ims_app.SaleItem; AuditLog = ims_app.AuditLog
    old = sqlite3.connect(SOURCE); old.row_factory = sqlite3.Row
    user_map = {}
    for r in old.execute('SELECT * FROM users ORDER BY id'):
        role = {'super_admin':'admin','admin':'admin','manager':'manager','user':'staff','staff':'staff'}.get((r['role'] or 'user').lower(),'staff')
        username = (r['email'] or '').split('@')[0] or f'user{r["id"]}'
        base = username; i = 2
        while User.query.filter_by(username=username).first():
            username = f'{base}{i}'; i += 1
        u = User(id=str(uuid.uuid4()), username=username, email=r['email'], password_hash=r['password_hash'],
                 full_name=r['full_name'], role=role, is_active=bool(r['is_active']),
                 created_at=r['created_at'], updated_at=r['created_at'])
        db.session.add(u); db.session.flush(); user_map[r['id']] = u.id
    db.session.commit()

    # Import legacy user audit history.
    for r in old.execute('SELECT * FROM audit_logs ORDER BY id'):
        db.session.add(AuditLog(entity_type='user', entity_id=user_map.get(r['target_user_id']),
                                 action=r['action'], details=r['details'], user_id=user_map.get(r['actor_id']),
                                 timestamp=r['created_at']))

    products = {}
    for r in old.execute('SELECT * FROM orders ORDER BY id'):
        name = r['product_name']
        if name not in products:
            products[name] = Product(sku=f'LEGACY-{len(products)+1:05d}', name=name, category='Migrated',
                                     description='Migrated from legacy order data. Current on-hand stock was not available in the legacy database.',
                                     cost_price=0, selling_price=float(r['total_price'])/max(int(r['quantity']),1),
                                     quantity=0, unit='pcs', reorder_point=10, is_active=True, created_at=r['created_at'], updated_at=r['created_at'])
            db.session.add(products[name]); db.session.flush()
        total=float(r['total_price']); qty=int(r['quantity']); sid=str(uuid.uuid4())
        sale=Sale(id=sid, reference=f'LEGACY-{int(r["id"]):06d}', customer_id=None, sale_date=str(r['created_at'])[:10],
                  status='completed', subtotal=total, tax_amount=0, discount_amount=0, total_amount=total,
                  notes='Migrated from legacy orders table.', created_by=user_map.get(r['user_id']), created_at=r['created_at'], updated_at=r['created_at'])
        db.session.add(sale)
        db.session.add(SaleItem(id=str(uuid.uuid4()), sale_id=sid, product_id=products[name].id, quantity=qty,
                                unit_price=(total/qty if qty else 0), line_total=total))
    db.session.commit(); old.close()
    print('Migration completed successfully.')
