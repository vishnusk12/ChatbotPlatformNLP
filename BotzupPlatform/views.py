'''
Created on 30-Jul-2018

@author: Vishnu
'''

from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import permission_classes
from rest_framework import permissions
from .model import Model
from .config import create_cache
import spacy
  
nlp = spacy.load('en')

from pymongo import MongoClient

host = "mongodb://botzupadmin:NocBs3038pMbumhq@13.228.152.246:32481/chatbotplatform?authSource=admin"
db_client = MongoClient(host, port=32481)

import tensorflow_hub as hub
import tensorflow as tf
 
module_url = "https://tfhub.dev/google/universal-sentence-encoder-large/2"
  
g = tf.Graph()
with g.as_default():
    similarity_input_placeholder = tf.placeholder(tf.string, shape=(None))
    embed = hub.Module(module_url, trainable=True)
    encoding_tensor = embed(similarity_input_placeholder)
    init_op = tf.group([tf.global_variables_initializer(), tf.tables_initializer()])
g.finalize()
sess = tf.Session(graph=g)
sess.run(init_op)

from .similar import Similar

@permission_classes((permissions.AllowAny,))
class Sim(viewsets.ViewSet):
    def create(self, request):
        CACHE_ID = 'CONSTANT5'
        question = request.data
        if 'user_id' in question:
            CACHE_ID = question['user_id']
        req_cache = create_cache(CACHE_ID)
        result = Similar(question['messageText'], question['id'])
        final_result = Model(result + req_cache.cache[:5])
        if 'contexts' in final_result:
            req_cache.cache = final_result['contexts']
            req_cache.user.save()
            req_cache.save()
        return Response(final_result)
