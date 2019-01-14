# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lxml import etree
import json
import re

from .hook_test_case import HookTestCase
from kpi.constants import INSTANCE_FORMAT_TYPE_XML


class ParserTestCase(HookTestCase):

    def test_json_parser(self):
        hook = self._create_hook(subset_fields=["id", "subgroup1", "q3"])

        ServiceDefinition = hook.get_service_definition()
        submissions = hook.asset.deployment.get_submissions()
        uuid = submissions[0].get("id")
        service_definition = ServiceDefinition(hook, uuid)
        expected_data = {
            "group1/q3": u"¿Cómo está en el grupo uno la segunda vez?",
            "group2/subgroup1/q4": u"¿Cómo está en el subgrupo uno la primera vez?",
            "group2/subgroup1/q5": u"¿Cómo está en el subgrupo uno la segunda vez?",
            "group2/subgroup1/q6": u"¿Cómo está en el subgrupo uno la tercera vez?",
            "id": 1
        }
        self.assertEquals(service_definition._get_data(), expected_data)

    def test_xml_parser(self):
        self.asset_xml = self.create_asset(
            "some_asset_with_xml_submissions",
            content=json.dumps(self.asset.content),
            format="json")
        self.asset_xml.deploy(backend='mock', active=True)
        self.asset_xml.save()

        hook = self._create_hook(subset_fields=["id", "subgroup1", "q3"], format_type=INSTANCE_FORMAT_TYPE_XML)

        ServiceDefinition = hook.get_service_definition()
        submissions = hook.asset.deployment.get_submissions(format_type=INSTANCE_FORMAT_TYPE_XML)
        xml_doc = etree.fromstring(submissions[0])
        tree = etree.ElementTree(xml_doc)
        uuid = tree.find("id").text

        service_definition = ServiceDefinition(hook, uuid)
        expected_etree = etree.fromstring(("<{asset_uid}>"
                         "   <group1>"
                         "      <q3>¿Cómo está en el grupo uno la segunda vez?</q3>"
                         "   </group1>"
                         "   <group2>"
                         "      <subgroup1>"
                         "          <q4>¿Cómo está en el subgrupo uno la primera vez?</q4>"
                         "          <q5>¿Cómo está en el subgrupo uno la segunda vez?</q5>"
                         "          <q6>¿Cómo está en el subgrupo uno la tercera vez?</q6>"
                         "      </subgroup1>"
                         "   </group2>"
                         "   <id>{id}</id>"
                         "</{asset_uid}>").format(
            asset_uid=self.asset_xml.uid,
            id=uuid)
        )
        expected_xml = etree.tostring(expected_etree, pretty_print=True)

        def remove_whitespace(str_):
            return re.sub(r">\s+<", "><", str_)

        self.assertEquals(remove_whitespace(service_definition._get_data()),
                          remove_whitespace(expected_xml))
