from django.db import models
import fake_geoip_lookup_xyz


class Widget(models.Model):
    name = models.CharField(max_length=100)

    def locate(self):
        return fake_geoip_lookup_xyz.lookup(self.name)
