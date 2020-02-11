class Question < ApplicationRecord
  belongs_to :user, optional: true

  validates :text, presence: true,
                   length: {maximum: 255}
  validates :user, presence: true
end
