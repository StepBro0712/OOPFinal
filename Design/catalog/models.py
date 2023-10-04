from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models
from django.utils.crypto import get_random_string


class User(AbstractUser):
    name = models.CharField(max_length=200, verbose_name='Имя', blank=False)
    surname = models.CharField(max_length=200, verbose_name='Фамилия', blank=False)
    patronymic = models.CharField(max_length=200, verbose_name='Отчество', blank=True)
    username = models.CharField(max_length=200, verbose_name='Логин', unique=True, blank=False)
    email = models.EmailField(max_length=200, verbose_name='Почта', unique=True, blank=False)
    password = models.CharField(max_length=200, verbose_name='Пароль', blank=False)
    role = models.CharField(max_length=200, verbose_name='Роль',
                            choices=(('admin', 'Администратор'), ('user', 'Пользователь')), default='user')

    def __str__(self):
        return self.name


def get_name_file(instance, filename):
    return '/'.join([get_random_string(length=5) + '_' + filename])


class Application(models.Model):
    name = models.CharField(max_length=200, verbose_name='Название', blank=False)
    username = models.ForeignKey('User', on_delete=models.SET_NULL, null=True)
    description = models.TextField(max_length=1000, verbose_name='Описание', help_text='Напишите описание ', blank=False)
    categories = models.ForeignKey('Categorise', verbose_name='Категория', on_delete=models.CASCADE)
    image = models.ImageField(max_length=254, upload_to=get_name_file, verbose_name='Эскиз')
    status = models.CharField(max_length=200, verbose_name='Статус',
                              choices=(('new', 'Новая'), ('in work', 'Принято в работу'), ('done', 'Выполнено')),
                              default='new')
    date = models.DateField(verbose_name='Дата добавления', auto_now_add=True)
    img = models.ImageField(max_length=254, upload_to=get_name_file, null=True)
    comment = models.TextField(max_length=1000, help_text="Комментарий", blank=True)

    def __str__(self):
        return self.name


class Categorise(models.Model):
    name = models.CharField(max_length=200, help_text="Напишите категорию", blank=False)

    def __str__(self):
        return self.name
