from flask import Flask, render_template, flash, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import check_password_hash, generate_password_hash
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,TextAreaField, \
                    DateTimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import getpass, pymysql, sys
from hashlib import md5
import datetime
import pyodbc
from SouthernConnections_Forms import SignUpForm, LoginForm, AddMeetupForm,userProfileForm, AddComment,\
UpdateMeetupForm,SearchMeetupForm,JoinMeetup,LeaveGroupForm,LeaveMeetup,SearchGroupsForm,\
LinkedinForm, ChangePassword, ChangeMajor, DeleteMeetup, ProfilePic, SearchForum, CreatePost
from time import sleep
import csv
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from parsel import Selector
from werkzeug import secure_filename


app = Flask(__name__)
app.config['SECRET_KEY'] = '@N4j* kMr3%M 2o9$ f5h*G'
app.db = None
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bootstrap = Bootstrap(app)
moment = Moment(app)


# flask user mixin code - used to store current user data and check password against hash
class User(UserMixin):
	def __init__(self, email, password, role):
		self.id = email
		self.pass_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
		self.role = role

# logic to connect to the database to pull and query data
def connect_db():
	if not app.db:
		app.db = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};SERVER=DESKTOP-IO3MC37;DATABASE=SouthernConnections;TRUSTED_CONNECTION=yes;")
	else:
		print('Connected', file=sys.stderr)

# used to check if user signing up already has an account
def check_duplicate_user(email):
	if not app.db:
		connect_db()
	c = app.db.cursor()
	c.execute("SELECT * FROM MemberProfile WHERE Email=?", email)
	dup_user = c.fetchall()
	c.close()
	if not dup_user:
		return False
	else:
		return True

#logic to check if the email being used for signup is a southernct.edu domain
def check_scsu_email(email):
	split_email = email.split('@')
	if split_email[1] != 'southernct.edu':
		return False
	else:
		return True

#error handler 1
@app.errorhandler(404)
def page_not_found(e):
	print('at 400', file=sys.stderr)
	return render_template('404.html'), 404

#error handler 2
@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

#login manager - loads the user data from the database
@login_manager.user_loader
def load_user(id):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	c.execute("SELECT email,passwd,userType FROM MemberProfile WHERE email=?", id)
	user_values = c.fetchall()
	c.close()
	if not user_values:
		return None
	else:
		return User(user_values[0][0],user_values[0][1],user_values[0][2])

#landing page for a user not logged in first coming to the site
@app.route('/')
def base_page():
	return render_template('index.html')

# home page for a user who is logged in
@app.route('/home/')
@login_required
def homepage():
	return render_template('main_page.html')


#sign up logic for new users
@app.route('/sign-up/', methods=['GET', 'POST'])
def signup():
	if not app.db:
		connect_db()
	email = None	#initializes empty form fields
	first_name = None
	last_name = None
	password = None
	password2 = None
	major = None
	minor = None
	gradyear = None
	form = SignUpForm()
	c= app.db.cursor()
	c.execute("Select id, major from majors order by major")
	form.major.choices = c.fetchall() #populates major select list choices
	if form.validate_on_submit():
		email = form.email.data
		form.email.data = ''
		first_name= form.first_name.data
		form.first_name.data = ''
		last_name = form.last_name.data
		form.last_name.data = ''
		password = form.password.data
		form.password.data = ''
		password2 = form.password2.data
		major = form.major.data
		form.password2.data = ''
		minor = form.minor.data
		form.minor.data = ''
		gradyear = form.gradyear.data
		form.gradyear.data = ''		#saves the input from form fields into parameters so they can be input into the database
		if minor == '':
			minor = [] #saves minor as an empty tuple for later use with html
		if check_duplicate_user(email) == True: #uses the function created to check if this user already has an account on this site
			flash("You are already signed up")
			return redirect(url_for('login'))
		elif check_scsu_email(email) == True: # checks that the email address is a southernct.edu domain
			params = (email,first_name,last_name,major,gradyear,password)
			c.execute("{CALL get_new_user (?,?,?,?,?,?)}", params) #calls stored procedure that saves user info into a table, and captures major group membership
			app.db.commit()
			c.close()
			user=load_user(email)
			login_user(user)
			return redirect(url_for('linkedin'))
		else:
			flash('Email must be a @southernct.edu email') #if email is not southernct.edu - flash this message
			return redirect(url_for('signup'))
	return render_template('sign_up.html', form=form, email=email, last_name=last_name,\
			first_name=first_name, password=password,\
			password2=password2, major=major, minor=minor, gradyear=gradyear)

# linkedin route - captures login and profile information from users linkedin profile
# users are routed here after they successfully sign up
@app.route('/linkedin', methods=['GET', 'POST'])
@login_required
def linkedin():
	if not app.db:
		connect_db()
	form=LinkedinForm()
	user= None
	email = current_user.id
	passwd= None
	link=None
	minor = None
	c=app.db.cursor()
	c.execute('select fname,lname from memberprofile where email=?', email)
	name = c.fetchall()
	fname = name[0][0]
	lname = name[0][1]
	if request.method == 'POST':
		user = form.user.data
		passwd = form.passwd.data
		link = form.URL.data
		driver = webdriver.Chrome('C:/Users/mcevi/mcevi/chromedriver.exe') #initializes driver that will automate the task of scraping linkedin data
		driver.get('https://www.linkedin.com') #takes user to linkedin.com and enters the data it captured from the linkedin form
		sleep(5)
		username= driver.find_element_by_class_name('input__field')
		username.send_keys(user) #uses the classes within linkedin HTML to find the data to scrape
		password = driver.find_element_by_name('session_password')
		password.send_keys(passwd)
		login_button = driver.find_element_by_class_name('sign-in-form__submit-btn	')
		login_button.click() #finds sign in button and presses it through the driver
		sleep(2)
		driver.get(link)
		sleep(2)
		sel = Selector(text=driver.page_source)
		name = sel.xpath('//*[starts-with(@class, "inline t-24 t-black t-normal break-words")]/text()').get() #pulls first name and last name from profile
		name=name.strip() #strips the trailing whitespace
		headline= sel.xpath('//*[starts-with(@class, "mt1 t-18 t-black t-normal")]/text()').get() #pulls headline from linkedin profile
		headline=headline.strip()
		college = sel.xpath('//*[starts-with(@class, "pv-entity__school-name t-16 t-black t-bold")]/text()').get() #pulls college data if provided
		currentJob = sel.xpath('//*[starts-with(@class, "t-16 t-black t-bold")]/text()').get() #pulls job information if provided from linkedin
		company = sel.xpath('//*[starts-with(@class, "pv-entity__secondary-title t-14 t-black t-normal")]/text()').get() #the company they work for as shown on their linkedin profile
		concentration = sel.xpath('//*[starts-with(@class, "pv-entity__description t-14 t-normal mt4")]/text()').getall() 
		if concentration != []: #if statement that caputres major and minor for the database if it exists on linkedin
			major = concentration[0] 
			major = major.strip()
			if concentration[1] != []:
				minor = concentration[1]
				minor=minor.strip()
				minor=minor[7:] #cuts off the word 'minor: ' from the beginning
		location = sel.xpath('//*[starts-with(@class, "t-16 t-black t-normal inline-block")]/text()').get() #pulls city,state from linkedin profile
		location =location.strip()
		params = (name,headline,college,currentJob,company,minor,location,link,email) #updates the data it saved to DB when user signed up
		c.execute("update memberprofile set name = ?, headline=?,college = ?,currentJob=?,company = ?,\
			minor=?,location =?, linkedin =? where email = ?",params)
		driver.quit()
		app.db.commit()
		driver.quit()
		return redirect(url_for('edit_profile', username=current_user.id)) #redirects to edit profile to allow the user to confirm the data it pulled
	return render_template('linkedin.html', form=form)


@app.route('/success')
def success():
        return render_template('success.html')


@app.route('/edit-profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
        if not app.db:
                connect_db()
        c = app.db.cursor()
        c.execute("select * from MemberProfile where email = ?", username)
        user = c.fetchall()
        headline = user[0][11]
        about_me = user[0][7]
        first_name = user[0][2]
        last_name = user[0][3]
        minor = user[0][15]
        currentjob = user[0][13]
        company = user[0][14]
        location = user[0][16]
        gradyear = user[0][6]
        email = username
        form = userProfileForm()
        if request.method == 'GET':
        	form.headline.data = headline
        	form.about_me.data = about_me
        	form.first_name.data = first_name
        	form.last_name.data = last_name
        	form.minor.data = minor
        	form.currentjob.data = currentjob
        	form.company.data = company
        	form.location.data = location
        	form.gradyear.data = gradyear
        elif request.method == 'POST':
        	if form.validate_on_submit():
        		about_me = form.about_me.data
        		headline = form.headline.data
        		first_name = form.first_name.data
        		last_name = form.last_name.data
        		minor = form.minor.data
        		currentjob = form.currentjob.data
        		company = form.company.data
        		location = form.location.data
        		gradyear = form.gradyear.data
        		params = (first_name, last_name, gradyear, about_me, headline, currentjob, company, minor, location, username)
        		c.execute("UPDATE memberprofile SET fname=?, lname=?, gradyear=?, about=?, headline=?, currentJob=?, \
        			company=?, minor=?, location=? WHERE email=?", params)
        		app.db.commit()
        		c.close()
        		return redirect(url_for('user', username=email))
        return render_template('edit_profile.html', form=form, about_me=about_me, first_name= first_name, \
        last_name=last_name, headline=headline, minor= minor, currentjob=currentjob, company=company,\
        email = email,location=location, gradyear=gradyear)


@app.route('/forum', methods=['GET','POST'])
def forum():
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form = SearchForum()
	forum_search = None
	forums = []
	c.execute("select f.*, mp.profilepic, mp.fname, mp.lname,cast(createtime as time) as newtime, \
		cast(createdate as date) as newdate from forum f \
		inner join memberprofile mp on f.creator = mp.Email order by newdate desc, newtime desc")
	posts = c.fetchall()
	if form.validate_on_submit():
		forum_search=form.search_forum.data
		form.search_forum.data= ''
		forum_search= "%" + forum_search + "%"
		c.execute("{CALL forum_search(?)}", forum_search)
		forums= c.fetchall()
	return render_template('forum.html', posts=posts, form=form, forums=forums, forum_search=forum_search)


@app.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
	if not app.db:
		connect_db()
	c= app.db.cursor()
	form = CreatePost()
	title= None
	body = None
	tags = None
	if form.validate_on_submit():
		title= form.title.data
		body = form.body.data
		tags = form.tags.data
		c.execute("{CALL new_forum_post(?,?,?,?)}", title, body, current_user.id, tags)
		app.db.commit()
		c.execute('SELECT * from forum where creator=? and title=?', current_user.id, title)
		post = c.fetchall()
		postid= post[0][0]
		c.close()
		return redirect((url_for('individual_post', postid=postid)))
	return render_template('forum_post.html', form=form, title=title, body=body, tags=tags)

@app.route('/edit-post/<postid>', methods=['GET', 'POST'])
@login_required
def edit_post(postid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=CreatePost()
	title= None
	body = None
	tags = None
	c.execute('SELECT * from Forum where id =?', postid)
	post=c.fetchall()
	if request.method == 'GET':
		form.title.data = post[0][1]
		form.body.data = post[0][2]
		form.tags.data = post[0][6]
	elif request.method == 'POST':
		title = form.title.data
		body = form.body.data
		tags = form.tags.data
		c.execute ("UPDATE forum set title=?, body = ?, tags = ? where id = ?", title, body, tags, postid)
		app.db.commit()
		c.close()
		return redirect((url_for('individual_post', postid=postid)))
	return render_template('edit_post.html', form=form, title=title, body=body, tags=tags, post = post, postid=postid)

@app.route('/delete-post/<postid>', methods=['GET', 'POST'])
@login_required
def delete_post(postid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=DeleteMeetup()
	if form.validate_on_submit():
		c.execute('DELETE from forum where id=?', postid)
		c.execute('DELETE from forum_comments where forumid=?', postid)
		app.db.commit()
		c.close()
		return redirect((url_for('forum')))
	return render_template('delete_post.html', form=form, postid=postid)

@app.route('/comment/<postid>', methods=['GET','POST'])
@login_required
def comment(postid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=AddComment()
	comment = None
	if form.validate_on_submit():
		comment = form.comment.data
		c.execute("{CALL new_forum_comment(?,?,?)}", postid, comment, current_user.id)
		app.db.commit()
		c.close()
		return redirect(url_for('individual_post', postid=postid))
	return render_template('add_comment.html', form=form, comment=comment, postid=postid)

@app.route('/edit-comment/<commentid>', methods=['GET','POST'])
@login_required
def edit_comment(commentid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=AddComment()
	comment= None
	c.execute('SELECT * from forum_comments where id = ?', commentid)
	comments = c.fetchall()
	if request.method == 'GET':
		form.comment.data = comments[0][2]
	elif request.method == 'POST':
		comment = form.comment.data
		c.execute('UPDATE forum_comments set body = ? where id = ?', comment, commentid)
		app.db.commit()
		c.close()
		return redirect((url_for('individual_post', postid= comments[0][1])))
	return render_template('edit_comment.html', form=form, comment=comment, commentid=commentid, comments=comments)

@app.route('/delete-comment/<commentid>', methods=['GET', 'POST'])
@login_required
def delete_comment(commentid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=DeleteMeetup()
	c.execute("SELECT * from forum_comments where id =?", commentid)
	comments=c.fetchall()
	if form.validate_on_submit():
		c.execute('DELETE from forum_comments where id=?', commentid)
		app.db.commit()
		c.close()
		return redirect((url_for('individual_post', postid=comments[0][1])))
	return render_template('delete_comment.html', form=form, commentid=commentid, comments=comments)

@app.route('/individual-post/<postid>', methods=['GET', 'POST'])
@login_required
def individual_post(postid):
	if not app.db:
		connect_db()
	c= app.db.cursor()
	c.execute("SELECT f.*, mp.profilepic, mp.fname, mp.lname,cast(createtime as time) as newtime from forum f \
		inner join memberprofile mp on f.creator = mp.Email where f.id=? order by newtime desc", postid)
	posts=c.fetchall()
	c.execute("SELECT fc.*,mp.fname,mp.lname, cast(commenttime as time) as new_time, cast(commentdate as date) as newdate \
		from forum_comments fc inner join MemberProfile mp on mp.Email = fc.creator \
		where forumid =? order by newdate desc, new_time desc", postid)
	comments = c.fetchall()
	return render_template('post_individual.html', posts=posts, comments=comments)



@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user(username):
	if not app.db:
		connect_db()
	c = app.db.cursor()
	c.execute("Select * from MemberProfile where email =?", username)
	user_data = c.fetchall()
	minor=None
	profilepic = user_data[0][17]
	linkedin = user_data[0][18]
	c.execute("select * from meetmembers where members = ?", username)
	meetups = c.fetchall()
	event_dates = []
	for meetup in meetups:
		c.execute("SELECT * FROM meetup WHERE title = ?", meetup[1])
		event_dates.append(c.fetchone())
	c.execute("select m.major from memberprofile mp inner join majors m on m.id = mp.major \
		WHERE email=?", user_data[0][1])
	group = c.fetchall()
	group = group[0][0]
	c.execute("select title from meetmembers where members = ? ", username)
	if user_data == [] or username== '':
		flash('User not found')
		return redirect(url_for('base_page'))
	if current_user.is_anonymous:
		return redirect(url_for('login'))
	else:
		user_object = username
		about_me = user_data[0][7]
		email= user_data[0][1]
		role = user_data[0][8]
		name = user_data[0][10]
		minor=user_data[0][15]
		headline=user_data[0][11]
		college=user_data[0][12]
		if user_data[0][13] != '' and user_data[0][14] != '':
			currentJob=user_data[0][13] + ', at ' + user_data[0][14]
		else:
			currentJob = ''
		location=user_data[0][16]
		gradyear = user_data[0][6]
		interests= user_data[0][4]
		profilepic = user_data[0][17]
		c.close()
	return render_template('user.html', user=user_object, about_me=about_me,\
                                name=name, role=role, events=meetups, linkedin=linkedin, \
                                event_dates=event_dates, groups=group, minor=minor, profilepic=profilepic,\
                                currentJob=currentJob, location=location, headline=headline, email=email,\
                                group=group, interests=interests, gradyear=gradyear, username = username	)

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=ProfilePic(csrf_enabled=False)
	filepath = None
	if form.validate_on_submit():
		filename = secure_filename(form.file.data.filename)
		form.file.data.save('C:/Users/mcevi/Desktop/SouthernConnections/static/images/' + filename)
		filepath='/static/images/' + filename
		c.execute("update memberprofile set profilepic=? where email=?", filepath, current_user.id)
		app.db.commit()
		c.close()
		return redirect(url_for('user', username=current_user.id))
	return render_template('upload.html', form=form, filepath=filepath)

#HTML page done
@app.route('/login/', methods=['GET', 'POST'])
def login():
	if not app.db:
		connect_db()
	email = None
	password = None
	form = LoginForm()
	c=app.db.cursor()
	if form.validate_on_submit():
		email = form.email.data
		form.email.data = ''
		password = form.password.data
		form.password.data = ''
		user = load_user(email)
		if user != None:
			valid_password = check_password_hash(user.pass_hash, password)
		if user is None or not valid_password:
			flash('Invalid Username or Password')
			print('Invalid username or password', file=sys.stderr)
			redirect(url_for('login'))
		else:
			login_user(user)
			return redirect(url_for('user', username=current_user.id))
	return render_template('login.html', form=form, email=email, password=password)


# Logout Route
@app.route('/logout')
def logout():
        if current_user.is_anonymous:
                return render_template('index.html')
        else:
                name = current_user.id
                logout_user()
                return render_template('index.html')



@app.route('/change-password/<username>', methods = ['GET','POST'])
@login_required
def change_password(username):
	if not app.db:
		connect_db()
	c = app.db.cursor()
	form = ChangePassword()
	c.execute("select passwd from memberprofile where email = ?", username)
	passwd=c.fetchall()
	password = passwd[0][0]
	confirm = None
	if request.method == 'GET':
		form.password.data = passwd
	elif request.method == 'POST':
		if form.validate_on_submit():
			password = form.password.data
			form.password.data = ''
			c.execute("Update memberprofile set passwd=? where email = ?", password, username)
			app.db.commit()
			c.close()
			return redirect((url_for('user', username=username)))
	return render_template('change_password.html', form=form, password=password, confirm=confirm, username=username)


@app.route('/add-meetup', methods=['GET', 'POST'])
@login_required
def add_meetup():
	if not app.db:
		connect_db()
	title = None
	place = None
	event_date = None
	event_time = None
	description = None
	group= None
	major = None
	tags = None
	form = AddMeetupForm()
	c= app.db.cursor()
	c.execute("select mp.major, m.major from memberprofile mp inner join majors m on m.id = mp.major \
			where email = ?", current_user.id)
	form.major.choices = c.fetchall()
	c=app.db.cursor()
	if form.validate_on_submit():
		title = form.title.data
		form.title.data = ''
		place = form.place.data
		form.place.data = ''
		description = form.description.data
		form.description.data = ''
		event_date = form.event_date.data
		form.event_date.data = ''
		event_time = form.event_time.data
		major = form.major.data
		tags = form.tags.data
		form.tags.data = ''
		c.execute("select * from meetup where title=? and groupid=?", title,major)
		dup_meetup=c.fetchall()
		if dup_meetup != []:
			flash('An event already exists in this group with that title.')
			redirect((url_for('add_meetup')))
		else:
			params = (title,place,event_date,event_time, current_user.id,description,major,tags)
			c.execute("{CALL usp_getnew_meetup (?,?,?,?,?,?,?)}", params)
			app.db.commit()
			c.execute("select * from meetup where title=? and groupid=?", title, major)
			meetup=c.fetchall()
			meetupid= meetup[0][0]
			c.close()
			return redirect((url_for('meetup', meetupid=meetupid)))
	return render_template('add_meetup.html', form=form, title=title, place=place, event_date=event_date, \
		description=description, group=major, tags = tags)


@app.route('/search-meetups', methods=['GET','POST'])
@login_required
def search_meetups():
	if not app.db:
		connect_db()
	c=app.db.cursor()
	meetups = []
	title = None
	form= SearchMeetupForm()
	c.execute("select mu.*, m.major, cast(time as time) as newtime from meetup mu\
		inner join majors m on m.id = mu.groupid order by mu.date desc, newtime desc")
	all_meetups=c.fetchall()
	if form.validate_on_submit():
		title=form.title.data
		form.title.data=''
		title = "%" + title + "%"
		c.execute("{CALL meetup_search (?)}", title)
		meetups= c.fetchall()
	return render_template('meetup_search.html', form=form, title=title, meetups=meetups, all_meetups=all_meetups)




#update events route
@app.route('/update-meetup/<meetupid>', methods=['GET', 'POST'])
@login_required
def update_meetup(meetupid):
	if not app.db:
		connect_db()
	form = UpdateMeetupForm()
	c=app.db.cursor()
	place = None
	event_date = None
	event_time = None
	tags = None
	description= None
	c.execute("SELECT * FROM Meetup WHERE ID=?", meetupid)
	meetup = c.fetchall()
	title = meetup[0][1]
	date = meetup[0][3]
	time = meetup[0][6]
	if request.method == 'GET':
		form.place.data = meetup[0][2]
		form.description.data = meetup[0][4]
		form.tags.data = meetup[0][8]
		c.execute("select title from majorgroup where id =?", meetup[0][5])
		major=c.fetchall()
		form.major.data = major[0][0]
	if request.method == 'POST':
		if form.validate_on_submit():
			place = form.place.data
			form.place.data = ''
			description = form.description.data
			form.description.data = ''
			event_date = form.event_date.data
			form.event_date.data = ''
			event_time = form.event_time.data
			form.event_time.data = ''
			tags = form.tags.data
			form.tags.data = ''
			params = (meetupid,place, event_date, event_time,description, tags)
			c.execute("{CALL update_meetup(?,?,?,?,?,?)}", params)
			app.db.commit()
			return redirect((url_for('meetup', meetupid=meetupid)))
	return render_template('update_meetup.html', form=form, description=description, event_date=event_date, \
		title=title, date = date, time=time, meetupid=meetupid, tags = tags)


@app.route('/majors/', methods=['GET', 'POST'])
@login_required
def majors():
	if not app.db:
		connect_db()
	department = None
	form = SearchGroupsForm()
	groups = []
	c=app.db.cursor()
	print(groups)
	c.execute("select id,departmentName from department order by departmentName")
	form.department.choices = c.fetchall()
	if form.validate_on_submit:
		department = form.department.data
		c.execute("select major,department,school from majors m where m.departmentid=?",department)
		groups = c.fetchall()
		c.execute("select major from majors where departmentid=?", department)
		groupName = c.fetchall()
	return render_template('major_search.html', groups=groups, form=form, department=department)


@app.route('/major/<groupName>', methods=['GET', 'POST'])
@login_required
def major_group(groupName):
	if not app.db:
		connect_db()
	c = app.db.cursor()
	user=current_user.id
	c.execute("select id from majors  where major=?",groupName)
	groupid = c.fetchone()
	c.execute("SELECT * FROM majorgroup WHERE title =?",groupName)
	groups = c.fetchone()
	c.execute("select id, title, description, place, date, time from meetup where groupid =? ", groupid)
	events=c.fetchall()
	c.close()
	return render_template('major_page_individual.html', \
		user=user, groupName=groupName, groups=groups, events=events)


@app.route('/change-major/<username>', methods = ['GET','POST'])
@login_required
def change_major(username):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form=ChangeMajor()
	major = None
	c.execute("Select id,major from majors")
	form.major.choices = c.fetchall()
	if form.validate_on_submit():
		major = form.major.data
		form.major.data = ''
		c.execute("update memberprofile set major = ? where email = ?", major, username)
		c.execute("insert into groupmembers(id,member) values (?,?)", major, username)
		c.execute("delete from groupmembers where id = ? and member = ?", major, username)
		app.db.commit()
		c.close()
		return redirect((url_for('user', username=username)))
	return render_template('change_major.html', username=username, form=form, major=major)

@app.route('/meetup/<meetupid>', methods=['GET','POST'])
@login_required
def meetup(meetupid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	c.execute("SELECT * FROM meetup WHERE id =?", meetupid) #gets all information from the database where the id = meetupid
	meetup = c.fetchall()
	c.execute("SELECT * FROM majors where id = ?", meetup[0][5]) #grabs the major group this meetup belongs to
	group_title=c.fetchall()
	group=group_title[0][1] #pulls the group title from the tuple
	c.execute("select mp.email,fname, lname from memberprofile mp \
		inner join meetmembers mm on mm.members = mp.email\
		where mm.meetupid =?", meetupid) #pulls the attendees from the table
	attendees = c.fetchall()
	test = [] # initialize empty tuple for easier call in HTML
	c.execute("{CALL getmeetupdate(?,?)}", meetupid, meetup[0][3]) #fixes the date so it shows up as mon, dd, yyyy (easier to read)
	new_date= c.fetchall()
	for attendee in attendees: #iterates over all attendees to see if the current user is an attendee for this meetup. For use in HTML
		i=0
		if attendee[i] == current_user.id:
			test = attendee[i]
		else:
			i+=1
	date= new_date[0][0] # sets variables to be displayed in HTML
	title= meetup[0][1]
	address = meetup[0][2]
	time = meetup[0][6]
	creator = meetup[0][7]
	description = meetup[0][4]
	return render_template('meetup_page_individual.html', meetup=meetup, title=title, address=address, \
		date=date, time=time, description = description, attendees=attendees, creator = creator, \
		meetupid=meetupid, group=group, test=test)


@app.route('/my-meetups/<username>', methods=['GET','POST'])
@login_required
def my_meetups(username):
	if not app.db:
		connect_db()
	joined=[]
	my_meetups=[]
	c=app.db.cursor()
	c.execute("select distinct id,title, place, date, time from meetup where creator = ?", username)
	my_meetups = c.fetchall()
	c.execute("select distinct mm.meetupid,mm.title,place,date,time from meetmembers mm \
		inner join meetup mu on mu.id = mm.meetupid \
		inner join majors mj on mj.id = mu.groupid where members = ?", username)
	joined = c.fetchall()
	return render_template('my_meetups.html', my_meetups = my_meetups, joined = joined, username=username)


@app.route('/delete-meetup/<meetupid>', methods=['GET','POST'])
@login_required
def delete_meetup(meetupid):
	if not app.db:
		connect_db
	c=app.db.cursor()
	form = DeleteMeetup()
	c.execute("select * from meetup where id=? and creator=?", meetupid, current_user.id)
	meetup=c.fetchall()
	title = meetup[0][1]
	group=meetup[0][5]
	c.execute("select title from majorgroup where id = ?", group)
	major = c.fetchall()
	majorgroup= major[0][0]
	if form.validate_on_submit():
		c.execute("delete from meetup where id = ? and groupid=?", meetupid, group)
		c.execute("delete from meetmembers where meetupid=?", meetupid)
		app.db.commit()
		c.close()
		return redirect((url_for('my_meetups', username=current_user.id)))
	return render_template('delete_meetup.html', form=form, title=title, meetupid=meetupid)


@app.route('/join-meetup/<meetupid>', methods=['GET','POST'])
@login_required
def join_meetup(meetupid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form = JoinMeetup()
	c.execute("Select * from meetup where id=?", meetupid)
	meetup=c.fetchall()
	title=meetup[0][1]
	if form.validate_on_submit():
		c.execute("insert into meetmembers(meetupid,title,members) values (?,?,?)", meetupid,title,current_user.id)
		app.db.commit()
		c.close()
		return redirect((url_for('meetup', meetupid=meetupid)))
	return render_template('join_meetup.html', form=form, title=title, meetupid=meetupid)

@app.route('/leave-meetup/<meetupid>', methods=['GET', 'POST'])
@login_required
def leave_meetup(meetupid):
	if not app.db:
		connect_db()
	c=app.db.cursor()
	form= LeaveMeetup()
	c.execute("SELECT * FROM Meetup where id=?", meetupid)
	meetup = c.fetchall()
	title = meetup[0][1]
	if form.validate_on_submit():
		c.execute("delete from meetmembers where meetupid=? and members=?", meetupid, current_user.id)
		app.db.commit()
		c.close()
		return redirect((url_for('meetup', meetupid=meetupid)))
	return render_template('leave_meetup.html', form=form,title=title,meetupid=meetupid)


if __name__=='__main__':
    app.run()
