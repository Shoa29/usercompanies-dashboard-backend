from flask_security import UserMixin, RoleMixin
from dashboard import db



# Create a table of users and user roles
user_roles_table = db.Table('user_roles',
                            db.Column('users_id', db.Integer(), db.ForeignKey('users.id')),
                            db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')))
# Create a table of roles and permissions
roles_permissions_table = db.Table('roles_permissions',
                            db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')),
                            db.Column('permission_id', db.Integer(), db.ForeignKey('permissions.id')))
# Create a table of users and companies
users_companies_table = db.Table('user_companies',
                            db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
                            db.Column('company_id', db.Integer(), db.ForeignKey('companies.id')))
#Users Model
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(80))
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    active = db.Column(db.Boolean())

    roles = db.relationship('Roles', secondary=user_roles_table, backref='user', lazy=True)
    companies = db.relationship('Companies', secondary=users_companies_table, backref='user', lazy=True)

    def __repr__(self):
        return f'Users({self.username}, {self.email}, {self.password})'
    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "active": self.active,
            "roles": self.roles,
            "companies": self.companies
        }

    def has_roles(self, *args):
        return set(args).issubset({role.name for role in self.roles})
#Roles Model
class Roles(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    role_description = db.Column(db.String(255))

    permits = db.relationship('Permissions', secondary=roles_permissions_table, backref='role', lazy=True)

    def __repr__(self):
        return f'Roles({self.name}, {self.role_description})'
    def serialize(self):
        return {
            "id": self.id,
            "role_name": self.name,
            "role_description": self.role_description
        }

#User Permissions Model
class Permissions(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    permission_info = db.Column(db.String(255))

    def __repr__(self):
        return f'Permissions({self.name}, {self.permission_info})'
    def serialize(self):
        return {
            "id": self.id,
            "permission_name": self.name,
            "permission_info": self.permission_info
        }

#Company Model
class Companies(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    company_name = db.Column(db.String(80), unique=True, nullable=False)
    company_info = db.Column(db.String(255))

    def __repr__(self):
        return f'Companies({self.company_name}, {self.company_info})'
    def serialize(self):
        return {
            "id": self.id,
            "permission_name": self.company_name,
            "permission_info": self.company_info
        }
