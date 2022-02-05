from flask_restx import Model, fields

UserPayload = Model('UserPayload', {
    'username': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True),
    'roles': fields.List(fields.String)
})
UserUpdatePayload = Model('UserUpdatePayload', {
    'email': fields.String(required=True),
    'roles': fields.List(fields.String),
    'active': fields.Boolean(required=False, default=True)
})
UserReadPayload = Model('UserReadPayload', {
    'email': fields.String(required=True)
})
AuthLogin = Model('AuthLogin', {
    'email': fields.String(required=True),
    'password': fields.String(required=True)
})
CompanyPayload = Model('CompanyPayload', {
    'company_name': fields.String(required=True),
    'company_info': fields.String(required=False)
})
CompanyListPayload = Model('CompanyListPayload', {
    'email': fields.String(required=True),
    'companies': fields.List(fields.String)
})