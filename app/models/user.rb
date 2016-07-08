class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  devise :omniauthable, :omniauth_providers => [:facebook]

  def self.from_omniauth(outh_hash)
    password_hash = Devise.friendly_token[0,20]
    @user = User.find_by_email outh_hash[:info][:email]
    unless @user
      @user = User.create(email: outh_hash[:info][:email],
       password: password_hash, password_confirmation: password_hash)
    end
    return @user
  end
end
