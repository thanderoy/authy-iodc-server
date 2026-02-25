from rest_framework import permissions, viewsets, generics
from rest_framework.response import Response
from modules.entities.models import Entity
from modules.entities.serializers import EntitySerializer, EntityMeSerializer
from modules.entities.forms import CustomUserCreationForm
from django.views.generic.edit import CreateView
from django.urls import reverse_lazy
from django.contrib.auth import login


class RegisterView(CreateView):
    template_name = "registration/register.html"
    form_class = CustomUserCreationForm
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        response = super().form_valid(form)
        login(self.request, self.object)
        return response


class EntityViewSet(viewsets.ModelViewSet):
    queryset = Entity.objects.all()
    serializer_class = EntitySerializer
    permission_classes = [permissions.IsAuthenticated]


class EntityMeViewset(generics.RetrieveUpdateAPIView):
    queryset = None
    serializer_class = EntityMeSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data

        return Response(data)
