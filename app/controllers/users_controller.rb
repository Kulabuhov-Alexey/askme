class UsersController < ApplicationController
  def index
  end

  def new
  end

  def edit
  end

  def show
    @user = User.new(
        name: 'Vadim',
        username: 'installero',
        avatar_url: 'http://megocomp.ru/wp-content/uploads/2012/03/error.jpg'
    )
  end
end
