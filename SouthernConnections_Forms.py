from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField,PasswordField,TextAreaField, \
                    DateTimeField, IntegerField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.fields.html5 import DateField
from wtforms_components import TimeField, DateRange, read_only
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, InputRequired
from datetime import datetime, date, timedelta


#Flask Form Classes


class SignUpForm(FlaskForm):
        email = StringField('SCSU Email:', validators = [DataRequired(), Email()])
        first_name = StringField('First Name:', validators = [DataRequired()])
        last_name = StringField('Last Name:', validators = [DataRequired()])
        password = PasswordField('Password:', validators = [DataRequired()])
        password2 = PasswordField('Re-enter Password:', validators = [DataRequired(), \
                 EqualTo('password')])
        major = SelectField('Major:')
        minor = StringField('Minor: ')
        gradyear = StringField('Graduation Year:', validators=[Length(max=4, message="Please enter a 4 digit year")])
        submit = SubmitField('Join')


class LoginForm(FlaskForm):
        email = StringField('SouthernCT Email:', validators = [DataRequired(), Email()])
        password = PasswordField('Password:', validators = [DataRequired()])
        submit = SubmitField('Sign in')


class userProfileForm(FlaskForm):
    first_name = StringField('First Name:', validators = [DataRequired(message = 'You must provide your First Name')])
    last_name = StringField('Last Name: ', validators = [DataRequired(message = 'You must provide your Last Name')])
    minor = StringField('Minor: ')
    headline = StringField('Headline: ', validators = [DataRequired()])
    currentjob = StringField('Current Job Title:')
    company= StringField('Current Company:')
    location = StringField('Location (City, State): ', validators = [DataRequired('Please provide your current location')])
    gradyear = StringField('Graduation Year:', validators=[Length(max=4, message="Please enter a 4 digit year")])
    about_me = TextAreaField('About Me:')
    submit = SubmitField('Update')

class SearchForum(FlaskForm):
    search_forum= StringField('Search Forum:')
    submit = SubmitField('Search')

class AddComment(FlaskForm):
    comment = TextAreaField('Comment:', validators=[DataRequired()])
    submit = SubmitField('Post')

class CreatePost(FlaskForm):
    title = StringField('Title:', validators=[DataRequired()])
    body = TextAreaField('Content:', validators=[DataRequired()])
    tags = StringField('Search Tags:', validators=[DataRequired()])
    submit = SubmitField('Post')

class LinkedinForm(FlaskForm):
    user = StringField('Username:', validators=[DataRequired()])
    passwd = PasswordField('Password:', validators=[DataRequired()])
    URL = StringField('Linkedin Profile URL:', validators=[DataRequired()])
    submit = SubmitField('Go')

class ChangePassword(FlaskForm):
    password = PasswordField('New Password', [InputRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm  = PasswordField('Repeat Password')
    submit = SubmitField('Change Password')


class AddMeetupForm(FlaskForm):
        title = StringField('Title:', validators = [DataRequired()])
        event_date = DateField('Date:', format='%Y-%m-%d', validators=[DateRange(min=(date.today()+timedelta(days=1)))])
        event_time = TimeField('Time:')
        place = StringField('Meeting Location:', validators = [DataRequired()])
        description = TextAreaField('Description:')
        tags = StringField('Search Tags:', validators=[DataRequired()])
        major = SelectField('Major:')
        submit = SubmitField('Submit')


class UpdateMeetupForm(FlaskForm):
        event_date = DateField('Date:', format='%Y-%m-%d', validators=[DateRange(min=(date.today()+timedelta(days=1)))])
        event_time = TimeField('Time:')
        major=StringField('Major:')
        place = StringField('Meeting Location:', validators = [DataRequired()])
        description = TextAreaField('Description:')
        tags = StringField('Search Tags:', validators=[DataRequired()])
        submit = SubmitField('Update')

        def __init__(self, *args, **kwargs):
            super(UpdateMeetupForm, self).__init__(*args, **kwargs)
            read_only(self.major)

class SearchMeetupForm(FlaskForm):
        title = StringField('Search Meetups:', validators = [DataRequired()])
        submit = SubmitField('Submit')

# Join Event
class JoinMeetup(FlaskForm):
        submit = SubmitField('RSVP')

# Leave Group
class LeaveGroupForm(FlaskForm):
        submit = SubmitField('Leave Group')

# Leave Group
class LeaveMeetup(FlaskForm):
        submit = SubmitField('Leave Meetup')

class DeleteMeetup(FlaskForm):
    submit = SubmitField('Yes, Delete')

# Search Groups
class SearchGroupsForm(FlaskForm):
        department = SelectField('Department:')
        submit = SubmitField('Go')

class ChangeMajor(FlaskForm):
    major = SelectField('Major:')
    submit = SubmitField('Save Changes')


class ProfilePic(FlaskForm):
    file=FileField(validators = [FileRequired()])
    submit= SubmitField('Upload')

