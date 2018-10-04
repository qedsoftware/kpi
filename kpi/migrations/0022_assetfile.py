# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import kpi.models.asset_file
from django.conf import settings
import jsonbfield.fields
import django.utils.timezone
import private_storage.fields
import private_storage.storage.files
import kpi.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('kpi', '0021_map-custom-styles'),
    ]

    operations = [
        migrations.CreateModel(
            name='AssetFile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uid', kpi.fields.KpiUidField(uid_prefix=b'af')),
                ('file_type', models.CharField(max_length=32, choices=[(b'map_layer', b'map_layer')])),
                ('name', models.CharField(max_length=255)),
                ('date_created', models.DateTimeField(default=django.utils.timezone.now)),
                ('content', private_storage.fields.PrivateFileField(storage=private_storage.storage.files.PrivateFileSystemStorage(), max_length=380, upload_to=kpi.models.asset_file.upload_to)),
                ('metadata', jsonbfield.fields.JSONField(default=dict)),
            ],
        ),
        # Why did `manage.py makemigrations` create these as separate operations?
        migrations.AddField(
            model_name='assetfile',
            name='asset',
            field=models.ForeignKey(related_name='asset_files', to='kpi.Asset'),
        ),
        migrations.AddField(
            model_name='assetfile',
            name='user',
            field=models.ForeignKey(related_name='asset_files', to=settings.AUTH_USER_MODEL),
        ),
    ]
