from rest_framework import permissions, viewsets, generics
from rest_framework.response import Response
from modules.entities.models import Entity
from modules.entities.serializers import EntitySerializer, EntityMeSerializer


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
