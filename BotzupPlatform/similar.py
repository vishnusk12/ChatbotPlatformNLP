'''
Created on 30-Jul-2018

@author: Vishnu
'''

from sklearn.metrics.pairwise import cosine_similarity
from .Entity import entities
from .views import db_client
from .views import sess, encoding_tensor, similarity_input_placeholder

def Similar(query, _id):
    data = list(db_client.chatbotplatform.intents.find({'chatBotId': str(_id)}, {'mappings':1, 'intentId': 1}))
    list_data = [list(i['mappings'].keys()) for i in data if 'mappings' in i and type(i['mappings']) == dict]
    flat_list = [item for sublist in list_data for item in sublist]
    array = [sess.run(encoding_tensor, feed_dict={similarity_input_placeholder:[query, i]}) for i in flat_list]
    similarity = [cosine_similarity(j[0:1], j) for j in array]
    similarity = [j[1] for i in similarity for j in i]
    index = [similarity.index(max(similarity)) for i in similarity if i > .8]
    try:
        similar_text = flat_list[index[0]]
        result = []
        for j in data:
            if 'mappings' in j and type(j['mappings']) == dict and similar_text in j['mappings']:
                result_dict = {}
                result_dict['response'] = similar_text
                result_dict['intentId'] = j['intentId']
                result_dict['parameters'] = entities(query)
                result_dict['entities'] = {}
                try:
                    result_dict['entities']['entityName'] = j['mappings'][similar_text]['entitiesData'][0]['entityName']
                    result_dict['entities']['name'] = j['mappings'][similar_text]['entitiesData'][0]['name']
                    result_dict['entities']['entityId'] = j['mappings'][similar_text]['entitiesData'][0]['id']
                except:
                    result_dict['entities']['entityName'] = ''
                    result_dict['entities']['name'] = ''
                    result_dict['entities']['entityId'] = ''
                result.append(result_dict)
        return result
    except:
        result = [{'response': 'No Match Found', 'intentId': '', 'parameters': entities(query), 'entities': {}}]
        return result
