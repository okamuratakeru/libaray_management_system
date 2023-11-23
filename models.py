from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime,timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, CheckConstraint, Enum
from sqlalchemy.orm import relationship

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

db = SQLAlchemy()


class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    password = Column(String, nullable=True)
    
    
    borrow_books = relationship("BorrowBook", back_populates="user", cascade="all, delete, delete-orphan")
    
    history_books = relationship('BorrowHistory',back_populates='user', cascade="all, delete, delete-orphan")
    
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    is_active = db.Column(db.Boolean, default=True)
    
    @property
    def is_authenticated(self):
        return True
    
    def get_id(self):
        return str(self.id)
      
    def is_locked(self):
        if not self.locked_until:
            return False
        now = datetime.utcnow()
        return now < self.locked_until



class Book(db.Model):
    __tablename__ = 'book'
    bookid = Column(Integer, primary_key=True, autoincrement=True)
    
    picture = Column(String, nullable=True)
    name = Column(Text , nullable=True)
    
    detail = Column(Text, nullable=True)
    author = Column(Text)
    release_date = Column(Text)
    publisher = Column(Text)
  
    genre = Column(Text)
    status = Column(Text,nullable=True,default='lending')
    added_on = Column(DateTime, default=datetime.utcnow, nullable=True)
    updated_on = Column(DateTime, default=datetime.utcnow, nullable=True)
    
    
    borrow_books = relationship("BorrowBook", back_populates="book", cascade="all, delete, delete-orphan")
    
    history_books = relationship('BorrowHistory',back_populates='book', cascade="all, delete, delete-orphan")


    



class BorrowBook(db.Model):
    __tablename__ = 'borrow_book'
    borrowbookid = Column(Integer, primary_key=True, autoincrement=True)
    bookid = Column(Integer, ForeignKey('book.bookid'), nullable=False)
    userid = Column(Integer, ForeignKey('user.id'), nullable=False)
    borrowed_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    returned_date = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=7), nullable=False)
    # return_date_time = Column(DateTime, nullable=False)
    # status = Column(Text, nullable=False)
    
    
    book = relationship("Book", back_populates="borrow_books")
    user = relationship("User", back_populates="borrow_books")

class BorrowHistory(db.Model):
    __tablename__ = 'borrow_history'
    borrowhistoryid = Column(Integer, primary_key=True, autoincrement=True)
    userid = Column(Integer, ForeignKey('user.id'),nullable=False)
    bookid = Column(Integer, ForeignKey('book.bookid'), nullable=False)
    borrowed_date = borrowed_date = Column(DateTime)
    returned_date = Column(DateTime)
    
    book = relationship("Book", back_populates="history_books")
    user = relationship("User", back_populates="history_books")
    
class Admin(db.Model,UserMixin):
    __tablename__ = 'admin'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=True)
    email = Column(String, nullable=True)
    password = Column(String, nullable=False)