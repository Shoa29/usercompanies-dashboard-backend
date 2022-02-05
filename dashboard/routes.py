import os
import timeit
from flask_user import roles_required, UserManager, roles_accepted
from flask_security import Security, SQLAlchemyUserDatastore
from dashboard import app, db, bcrypt, login_manager
from dashboard.models import Users, Roles, Permissions, Companies
from flask_restx import Api, Resource
from flask_login import login_user, current_user, logout_user, login_required
from dashboard.requests_model import UserPayload, UserUpdatePayload, UserReadPayload, AuthLogin, CompanyPayload, CompanyListPayload
#Tasks - user login, companies list thing, add permissions to roles,


user_manager = UserManager(app, db, Users)
# Create a datastore and instantiate Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, Users, Roles)
security = Security(app, user_datastore)

api = Api(app, version="1.0", title="Revelio Labs Dashboard")

# namespaces
ns_users = api.namespace('admin-dashboard')
ns_auth = api.namespace('user-auth')
ns_cl = api.namespace('company-lists')

@login_manager.user_loader
def user_loader(user_email):
    return Users.query.filter_by(email=user_email).first()

@app.before_first_request
def seed():
  db.drop_all()
  db.create_all()
  #adding permissions
  read_cl = Permissions(name='read_cl', permission_info='can read company lists')
  rw_cl = Permissions(name='rw_cl', permission_info='can modify company lists')
  read_ci = Permissions(name='read_ci', permission_info='can read company info')
  rw_ci = Permissions(name='rw_ci', permission_info='can modify company info')
  read_users = Permissions(name='read_users', permission_info='can read users info')
  rw_users = Permissions(name='rw_users', permission_info='can read write users info')
  db.session.add_all([read_cl, read_ci, read_users, rw_cl, rw_ci, rw_users])
  db.session.commit()
  admin = Roles(name='admin', role_description='Admin - can create, read, update, delete users')
  admin.permits.extend([rw_ci, rw_users, rw_cl])
  user_cl = Roles(name='user_cl', role_description='User - can access company lists tab')
  user_cl.permits.append(read_cl)
  user_ci = Roles(name='user_ci',role_description='User - can access company info tab')
  user_ci.permits.append(read_ci)
  db.session.commit()
  if not user_datastore.find_user(email="admin@admin.com"):
    hashed_pwd = bcrypt.generate_password_hash('admin').decode('utf-8')
    user_datastore.create_user(username='admin',email="admin@admin.com", password=hashed_pwd, roles=['admin'])
  if not user_datastore.find_user(email="test@test.com"):
    hashed_pwd = bcrypt.generate_password_hash('testing123').decode('utf-8')
    user_datastore.create_user(username='test',email="test@test.com", password=hashed_pwd, roles=['user_cl', 'user_ci'])
  db.session.commit()
  app.logger.info("initial setup")


@ns_auth.route('/logout')
class UserLogout(Resource):
  api.models[AuthLogin.name] = AuthLogin

  @ns_auth.doc(description="Logout User")
  @ns_auth.expect(AuthLogin)
  @login_required
  def post(self):
    user_cred = api.payload
    user = user_loader(user_cred['email'])
    if user:
      logout_user(user)
      return {'status':'User logged out'}
    else:
      return 400

@ns_auth.route('/login')
class UserLogin(Resource):
  api.models[AuthLogin.name] = AuthLogin
  @ns_auth.doc(description="Login User")
  @ns_auth.expect(AuthLogin)
  def post(self):
    user_cred = api.payload
    user = user_loader(user_cred['email'])
    if user and bcrypt.check_password_hash(user.password, user_cred['password']):
      login_user(user)
      return {'status':'user logged in successfully'},200
    else:
      print(user)
      print(bcrypt.check_password_hash(user.password, user_cred['password']))
      return {'status':'login failed'}, 404

@ns_auth.route('/register')
class UserRegister(Resource):
  api.models[UserPayload.name] = UserPayload
  @ns_auth.doc(description="Register users")
  @ns_auth.expect(UserPayload)
  def post(self):
    user_info = api.payload
    if not user_datastore.find_user(email=user_info['email']):
      hashed_pwd = bcrypt.generate_password_hash(user_info['password']).decode('utf-8')
      user_datastore.create_user(username=user_info['username'], email=user_info['email'], password=hashed_pwd, roles=user_info['roles'])
      db.session.commit()
      user = user_loader(user_info['email'])
      login_user(user)
      return {'status': 'user created'}, 200
    else:
      return {'error': 'user already exists with this email id'}, 404


#ADMIN REST APIS
#Admin USER CRUD Endpoints
@ns_users.route('/admin/user')
class User(Resource):
  api.models[UserReadPayload.name] = UserReadPayload
  api.models[UserUpdatePayload.name] = UserUpdatePayload
  api.models[UserPayload.name] = UserPayload

  @ns_users.doc(description="Get User")
  @roles_required('admin')
  @ns_users.expect(UserReadPayload)
  def get(self):
    user_info = api.payload
    user = user_loader(user_info['email'])
    res = user.serialize()
    db.session.commit()
    return res ,200

  @ns_users.doc(description="Create users")
  @roles_required('admin')
  @ns_users.expect(UserPayload)
  def post(self):
    user_info = api.payload
    if not user_datastore.find_user(email=user_info['email']):
      hashed_pwd = bcrypt.generate_password_hash(user_info['password']).decode('utf-8')
      user_datastore.create_user(username=user_info['username'], email=user_info['email'], password=hashed_pwd, roles=user_info['roles'])
      db.session.commit()
      return {'status':'user created'},200
    else:
      return {'error': 'user already exists with this email id'}, 404


  @ns_users.doc(description="Update User")
  @roles_required('admin')
  @ns_users.expect(UserUpdatePayload) # change payload to update
  def put(self):
    #change the role, username
    user_info = api.payload
    user = Users.query.filter_by(email=user_info['email']).first()
    if user is not None:
      user.roles.clear()
      for role in user_info['roles']:
        temp_role = user_datastore.find_role(role)
        user.roles.append(temp_role)
      #user.roles.extend(user_info['roles'])
      user.active = user_info['active']
    db.session.commit()
    return {'status':'user updated'},200

  @ns_users.doc(description="Delete User")
  @roles_required('admin')
  @ns_users.expect(UserReadPayload)
  def delete(self):
    user_info = api.payload
    user = user_loader(user_info['email'])
    user_datastore.delete_user(user)
    db.session.commit()
    return {'status':'user deleted'},200

#Admin Companies CRUD Endpoints
@ns_cl.route('/admin/user-companylist')
class Company(Resource):
  api.models[CompanyPayload.name] = CompanyPayload
  # create api -> create company
  @ns_users.doc(description="Get Company")
  @roles_accepted('admin', 'user_ci')
  @ns_users.expect(CompanyPayload)
  def get(self):
    # creating a company
    comp_info = api.payload
    comp_obj = Companies.query.filter_by(company_name=comp_info['company_name']).first()
    res = comp_obj.serialize()
    db.session.commit()
    return res ,200

  @ns_users.doc(description="Create Company")
  @roles_required('admin')
  @ns_users.expect(CompanyPayload)
  def post(self):
    #creating a company
    comp_info = api.payload
    comp_obj = Companies(company_name=comp_info['company_name'], company_info=comp_info['company_info'])
    db.session.add(comp_obj)
    db.session.commit()
    return {'status':'company created'},200

  @ns_users.doc(description="Delete Company")
  @roles_required('admin')
  @ns_users.expect(UserReadPayload)
  def delete(self):
    comp_info = api.payload
    comp_obj = Companies.query.filter_by(company_name=comp_info['company_name']).first()
    if comp_obj:
      db.session.delete(comp_obj)
      db.session.commit()
      return {'status':'company deleted'},200
    else:
      return {'error':'Company didnt exist'}

#Admin Companies CRUD Endpoints
@ns_cl.route('/admin/user-companylist')
class UserCompanyList(Resource):
  api.models[CompanyPayload.name] = CompanyPayload
  api.models[CompanyListPayload.name] = CompanyListPayload
  # create api -> create company
  @ns_users.doc(description="Get User Company list")
  @roles_accepted('admin', 'user_cl')
  @ns_users.expect(CompanyPayload)
  def get(self):
    # creating a company
    comp_info = api.payload
    user = user_loader(comp_info['email'])
    if user:
      cl = list(map(lambda x:x.id, user.companies))
      return {'user': comp_info['email'], 'companies':cl}, 200
    else:
      return {'error': 'user not found'}, 400

  @ns_users.doc(description="Associate User Companies")
  @roles_required('admin')
  @ns_users.expect(CompanyListPayload)
  def post(self):
    usercl = api.payload
    user = user_loader(email=usercl['email'])
    if user:
      for comp in usercl['companies']:
        temp_comp = Companies.query.filter_by(company_name=comp).first()
        user.companies.append(temp_comp)
      db.session.commit()
      return {'status':'user created'},200
    else:
      return {'error': 'user already exists with this email id'}, 404


  @ns_users.doc(description="Update User Company List")
  @roles_required('admin')
  @ns_users.expect(CompanyListPayload) # change payload to update
  def put(self):
    #change the role, username
    usercl = api.payload
    user = user_loader(usercl['email'])
    if user is not None:
      user.companies.clear()
      for comp in  usercl['companies']:
        temp_comp = Companies.query.filter_by(company_name=comp).first()
        user.roles.append(temp_comp)
    db.session.commit()
    return {'status':'user updated'},200

  @ns_users.doc(description="Delete User Company List")
  @roles_required('admin')
  @ns_users.expect(CompanyListPayload)
  def delete(self):
    usercl = api.payload
    user = user_loader(usercl['email'])
    if user is not None:
      user.companies.clear()
      db.session.commit()
      return {'status':'company list deleted'},200
    else:
      return {'error': 'user not found'}, 400