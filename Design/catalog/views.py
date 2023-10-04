from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.shortcuts import render, redirect
from django.views import generic, View
from django.views.generic import CreateView, UpdateView
from django.urls import reverse_lazy
from catalog.forms import RegisterUserForm
from django.contrib.auth.decorators import login_required
import datetime
from catalog.models import Application
from django.db.models import Q, Count
from django.forms import ModelForm, ClearableFileInput

from .forms import ApplicationForm
from .models import Application



class ApplicationAllListView(generic.ListView):
    model = Application
    template_name = 'index.html'
    paginate_by = 4

    def get_context_data(self, *args, **kwargs):
        context = super(ApplicationAllListView, self).get_context_data(*args, **kwargs)
        context['count'] = Application.objects.filter(status='done').count()
        return context

    def get_queryset(self):
        return Application.objects.filter(status='done').order_by('-date')


class RegisterView(CreateView):
    template_name = 'registration/register.html'
    form_class = RegisterUserForm
    success_url = reverse_lazy('login')


class ApplicationListView(LoginRequiredMixin, generic.ListView):
    model = Application
    template_name = 'profile.html'
    status = None

    def get(self, request, *args, **kwargs):
        if request.GET.get('status'):
            self.status = request.GET.get('status')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ApplicationListView, self).get_context_data(**kwargs)
        context['status_list'] = Application.objects.filter(Q(status='new') | Q(status='in work') | Q(status='done'))
        return context

    def get_queryset(self):
        if self.status:
            return Application.objects.filter(username=self.request.user, status=self.status)
        return Application.objects.filter(username=self.request.user).order_by('-date')


@login_required
def delete_application(request, pk):
    application = Application.objects.filter(username=request.user, pk=pk, status='new')
    if application:
        application.delete()
    return redirect('profile')


class CreateAppView(CreateView):
    model = Application
    form_class = ApplicationForm
    template_name = 'createapp.html'
    success_url = reverse_lazy('profile')

    def form_valid(self, form):
        # Получаем список всех выбранных файлов
        images = self.request.FILES.getlist('image')

        # Добавляем каждый файл к объекту модели
        for image in images:
            app = form.save(commit=False)
            app.image = image
            app.username = self.request.user
            app.date = datetime.date.today()
            app.save()

        return super().form_valid(form)
