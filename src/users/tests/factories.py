import factory
from factory.django import DjangoModelFactory

from users.models import User


class UserFactory(DjangoModelFactory):
    username = factory.Faker('user_name')
    email = factory.Faker('email')
    password = 'testpass123'

    class Meta:
        model = User
