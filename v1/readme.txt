***********************api documentation ***************
#############################
******* User *************
#############################

Base URL = http://pp.nwaresoft.com/v1/

******* LOGIN ********
URL = /v1/login
method =  POST
params: password,email 

******* LOGOUT ********
URL = /v1/logout
method =  get

	
******* REGISTRATION ********
URL = /v1/register
method =  POST
params : password,email,name 

******* change password ********
URL = /v1/changepassword
method =  POST
params : currentpassowrd,password 

******* edit user ********
URL = /v1/edituser
method =  POST
params : 'id','user_email','user_password','user_name

******* delete user ********
URL = /v1/deleteuser
method =  POST
params : 'id'

******* list user ********
URL = /v1/users
method =  get


	

#############################
******* Admin *************
#############################

 

********* add role
url=/admin/addrole
method : post
phram - id_role,  role_name,role_active,version,id_user_version,version_date

********* edit role
url=/admin/editrole
method : post
phram -id ,id_role,role_name,role_active,version,id_user_version,version_date

********* delete role
url=/admin/deleterole
method : post
phram - id

********* list role
url=/admin/listrole
method : get



Users - 

************users List
URL : /v1/admin/users
Method : GET


**************add user

URL : /v1/admin/adduser
params :- 'name', 'email', 'password', 'role_id'
METHOD : POST

************Edit user

url - /v1/admin/edituser
params :- id,name
method : POST

**************Delete user

url - v1/admin/deleteuser
params :- id
Method - post

*************change password

url - v1/admin/changepassword
params - id,currentpassword, password
Method - POST

******* Qrimage by admin  ********
URL = http://pp.nwaresoft.com/v1/qrimage
method =  POST
params  : email  


******** add/edit pharma detail

url = v1/admin/userdetail
method : post
phram - address1,address2,zip,town,latitude,longitude,phone,url,status

******** add/edit pharma detail

********add pharmacy

url = v1/admin/addpharmacy
method : post
phram - 'id', 'phone', 'address1','zip','town','email'

********list pharmacy

url = v1/admin/pharmacy
method : get
phram - 

********info pharma

url = /infopharma
method : post
phram - 'id'


********edit pharmacy

url = v1/admin/editpharmacy
method : post
phram - 'id', 'name'

********delete pharmacy

url = v1/admin/deletepharmacy
method : post
phram - 'id'


********add pharmacy day

url = v1/admin/addpharmacyday
method : post
phram - 'id', 'day_start_time', 'day_end_time','email'

********edit pharmacy day

url = v1/admin/editpharmacyday
method : post
phram - 'id','day_start_time','day_end_time'

********delete pharmacy day

url = v1/admin/deletepharmacyday
method : post
phram - id

********list pharmacy day

url = v1/admin/listpharmacyday
method : get
phram - 

********add pharmacy laboratory

url = v1/admin/addpharmacylaboratory
method : post
phram - 'laboratory_start_date', 'laboratory_end_date','email'

********edit pharmacy laboratory

url = v1/admin/editpharmacylaboratory
method : post
phram - 'id','laboratory_start_date','laboratory_end_date'

********delete pharmacy laboratory

url = v1/admin/deletepharmacylaboratory
method : post
phram - id

********list pharmacy laboratory

url = v1/admin/listpharmacylaboratory
method : get
phram - 

********add pharmacy role

url = v1/admin/addpharmacyrole
method : post
phram - 'id_role','pharmacy_role_start_date', 'pharmacy_role_end_date','email'

********edit pharmacy role

url = v1/admin/editpharmacyrole
method : post
phram - 'id','pharmacy_role_start_date','pharmacy_role_end_date'

********delete pharmacy role

url = v1/admin/deletepharmacyrole										
method : post
phram - id

********list pharmacy role

url = v1/admin/listpharmacyrole
method : get
phram - 


********list pharmacy dayschedule

url = /dayschedule
method : get
phram - idpharma

********add product

url =/admin/addproduct
method : post
phram - 'id_product','id_laboratory', 'product_name','product_description','product_indication','product_posology','id_typeprice'

********edit product

url =/admin/editproduct
method : post
phram - 'id','id_product','id_laboratory', 'product_name','product_description','product_indication','product_posology','id_typeprice'


********delete product
																
url = admin/deleteproduct										
method : post
phram - id

********list product

url = /admin/listproduct
method : get
phram - 

********* add product rating
url=/admin/addproductrating
method : post
phram - id_product,  product_rating_date, product_rating, product_rating_comments,product_rating_active,version,id_user_version,version_date

********* edit product rating
url=/admin/editproductrating
method : post
phram -id ,id_product,  product_rating_date, product_rating, product_rating_comments,product_rating_active,version,id_user_version,version_date

********* delete product rating
url=/admin/delete productrating
method : post
phram - id

********* listproduct rating
url=/admin/listproductrating
method : post
phram - 

********* add product tag
url=/admin/addproducttag
method : post
phram - 'id_product','id_tag', 'product_tag_score'

********* edit product tag
url=/admin/editproducttag
method : post
phram - 'id_product','id_tag', 'product_tag_score'

********* delete product tag
url=/admin/deleteproducttag
method : post
phram - id

********* list product tag
url=/admin/listproducttag
method : get
phram - 

********* add product composition
url=/admin/addproduct_composition
method : post
phram - 'id_product','id_ingredient','version','id_user_version'

********* edit product composition
url=/admin/editcomposition
method : post
phram - 'id','id_product','id_ingredient','version','id_user_version'

********* delete product composition
url=/admin/deletecomposition
method : post
phram - id

********* listproduct composition
url=/admin/listproductcomposition
method : get
phram - 

********* add product form
url=/admin/addproductform
method : post
phram - 'form_id','form_name','form_description'

********* edit product form
url=/admin/editproductform
method : post
phram - 'id','form_id','form_name','form_description'

********* delete product form
url=/admin/deleteproductform
method : post
phram - id

********* listproduct form
url=/admin/listproductform
method : get
phram - 

********* add product ingredient
url=/admin/addproductingredient
method : post
phram - 'ingredient_id','ingredient_name'

********* edit product ingredient
url=/admin/editproductingredient
method : post
phram - 'id','ingredient_id','ingredient_name'

********* delete product ingredient
url=/admin/deleteproductingredient
method : post
phram - id

********* listproduct ingredient
url=/admin/listproductingredient
method : get
phram - 

********* add product range price
url=/admin/addproductrangeprice
method : post
phram - 'range_price_id','range_price_text', 'range_price_picture'

********* edit product range price
url=/admin/editproductrangeprice
method : post
phram - 'id','range_price_id','range_price_text', 'range_price_picture'

********* delete product range price
url=/admin/deleteproductrangeprice
method : post
phram - id

********* list product range price
url=/admin/listproductrangeprice
method : get
phram - 

********* add product code
url=/admin/addproductcode
method : post
phram - id_product,  product_code, product_volume, id_coulour,product_code_active,version,id_user_version,version_date

********* edit product code
url=/admin/editproductcode
method : post
phram -id ,id_product,  product_code, product_volume, id_coulour,product_code_active,version,id_user_version,version_date

********* delete product code
url=/admin/deleteproductcode
method : post
phram - id

********* listproduct code
url=/admin/listproductcode
method : post
phram - 


*


********* add range
url=/admin/add range
method : post
phram - id_range,  id_laboratory,range_name,id_typerange,id_picture,range_active,version,id_user_version,version_date

********* edit range
url=/admin/edit role
method : post
phram -id ,id_range,  id_laboratory,range_name,id_typerange,id_picture,range_active,version,id_user_version,version_date

********* delete range
url=/admin/delete role
method : post
phram - id

********* list range
url=/admin/list user access
method : post
phram - 

********* add family
url=/admin/family
method : post
phram - 'id_family', 'family_name', 'id_family_next', 'id_tag'

********* edit family
url=/admin/editfamily
method : post
phram - 'id','id_family', 'family_name', 'id_family_next', 'id_tag'

********* delete family
url=/admin/deletefamily
method : post
phram - id

********* list family
url=/admin/listfamily
method : get
phram - 

********* add family tag
url=/admin/addfamilytag
method : post
phram - 'id_family_tag','id_family', 'id_tag'

********* edit family tag
url=/admin/editfamilytag
method : post
phram - 'id','id_family_tag','id_family', 'id_tag', 'id_family_next'

********* delete family tag
url=/admin/deletefamilytag
method : post
phram - id

********* list family tag
url=/admin/listfamilytag
method : get
phram - 

********* add contact
url=/admin/addcontact
method : post
phram - 'contact_email', 'contact_subject', 'contact_form'

********* edit contact
url=/admin/editcontact
method : post
phram - 'contact_id','contact_email', 'contact_subject', 'contact_form'


********* delete contact
url=/admin/deletecontact
method : post
phram - id

********* list contact
url=/admin/listcontact
method : get
phram - 

********* add contact
url=/admin/addcontact
method : post
phram - 'contact_email', 'contact_subject', 'contact_form'














