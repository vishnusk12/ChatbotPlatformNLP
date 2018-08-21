'''
Created on 30-Jul-2018

@author: Vishnu
'''

from .views import nlp
from nltk.corpus import names
import re
import webcolors
from .mappings import Date


def PERSON(text):
    text = text.title()
    split_text = text.split()
    doc = nlp(text)
    person = [ent.text for ent in doc.ents if ent.label_ == 'PERSON']
    list_person = []
    if len(person) > 0:
        dict_person = {}
        dict_person['@sys.given-name'] = [i.lower() for i in person]
        list_person.append(dict_person)
        return list_person
    elif len(person) == 0:
        labeled_names = ([(name, 'male') for name in names.words('male.txt')] + [(name, 'female') for name in names.words('female.txt')])
        for i in labeled_names:
            for j in split_text:
                if i[0] == j:
                    dict_person = {}
                    dict_person['@sys.given-name'] =  [i[0].lower()]
                    list_person.append(dict_person)
        return list_person
    else:
        return list_person
    
def GPE(text):
    doc = nlp(text.title())
    gpe = [ent.text for ent in doc.ents if ent.label_ == 'GPE']
    list_gpe = []
    if len(gpe) > 0:
        dict_gpe = {}
        dict_gpe['@sys.geo-place'] = [i.lower() for i in gpe]
        list_gpe.append(dict_gpe)
        return list_gpe
    else:
        return list_gpe
    
def NORP(text):
    doc = nlp(text.title())
    norp = [ent.text for ent in doc.ents if ent.label_ == 'NORP']
    list_norp = []
    if len(norp) > 0:
        dict_gpe = {}
        dict_gpe['@sys.nationality'] = [i.lower() for i in norp]
        list_norp.append(dict_gpe)
        return list_norp
    else:
        return list_norp
    
def FACILITY(text):
    doc = nlp(text.title())
    facility = [ent.text for ent in doc.ents if ent.label_ == 'FAC']
    list_facility = []
    if len(facility) > 0:
        dict_facility = {}
        dict_facility['@sys.facility'] = [i.lower() for i in facility]
        list_facility.append(dict_facility)
        return list_facility
    else:
        return list_facility
    
def ORG(text):
    doc = nlp(text.title())
    org = [ent.text for ent in doc.ents if ent.label_ == 'ORG']
    list_org = []
    if len(org) > 0:
        dict_org = {}
        dict_org['@sys.organisation'] = [i.lower() for i in org]
        list_org.append(dict_org)
        return list_org
    else:
        return list_org
    
def LOC(text):
    doc = nlp(text.title())
    loc = [ent.text for ent in doc.ents if ent.label_ == 'LOC']
    list_loc = []
    if len(loc) > 0:
        dict_loc = {}
        dict_loc['@sys.non-gpe'] = [i.lower() for i in loc]
        list_loc.append(dict_loc)
        return list_loc
    else:
        return list_loc
    
def PRODUCT(text):
    doc = nlp(text.title())
    product = [ent.text for ent in doc.ents if ent.label_ == 'PRODUCT']
    list_product = []
    if len(product) > 0:
        dict_product = {}
        dict_product['@sys.product'] = [i.lower() for i in product]
        list_product.append(dict_product)
        return list_product
    else:
        return list_product
    
def EVENT(text):
    doc = nlp(text.title())
    event = [ent.text for ent in doc.ents if ent.label_ == 'EVENT']
    list_event = []
    if len(event) > 0:
        dict_event = {}
        dict_event['@sys.event'] = [i.lower() for i in event]
        list_event.append(dict_event)
        return list_event
    else:
        return list_event
    
def WORK_OF_ART(text):
    doc = nlp(text.title())
    woa = [ent.text for ent in doc.ents if ent.label_ == 'WORK_OF_ART']
    list_woa = []
    if len(woa) > 0:
        dict_woa = {}
        dict_woa['@sys.work-of-art'] = [i.lower() for i in woa]
        return list_woa
    else:
        return list_woa
    
def LAW(text):
    doc = nlp(text.title())
    law = [ent.text for ent in doc.ents if ent.label_ == 'LAW']
    list_law = []
    if len(law) > 0:
        dict_law = {}
        dict_law['@sys.law'] = [i.lower() for i in law]
        list_law.append(dict_law)
        return list_law
    else:
        return list_law

def LANGUAGE(text):
    doc = nlp(text.title())
    language = [ent.text for ent in doc.ents if ent.label_ == 'LANGUAGE']
    list_language = []
    if len(language) > 0:
        dict_language = {}
        dict_language['@sys.language'] = [i.lower() for i in language]
        list_language.append(dict_language)
        return list_language
    else:
        return list_language
    
def PERCENT(text):
    doc = nlp(text.title())
    percent = [ent.text for ent in doc.ents if ent.label_ == 'PERCENT']
    list_percent = []
    if len(percent) > 0:
        dict_percent = {}
        dict_percent['@sys.percentage'] = [i.lower() for i in percent]
        list_percent.append(dict_percent)
        return list_percent
    else:
        return list_percent
    
def MONEY(text):
    doc = nlp(text.title())
    money = [ent.text for ent in doc.ents if ent.label_ == 'MONEY']
    list_money = []
    if len(money) > 0:
        dict_money = {}
        dict_money['@sys.unit-currency'] = [i.lower() for i in money]
        list_money.append(dict_money)
        return list_money
    else:
        return list_money
    
def QUANTITY(text):
    doc = nlp(text.title())
    quantity = [ent.text for ent in doc.ents if ent.label_ == 'QUANTITY']
    list_quantity = []
    if len(quantity) > 0:
        dict_quantity = {}
        dict_quantity['@sys.quantity'] = [i.lower() for i in quantity]
        list_quantity.append(dict_quantity)
        return list_quantity
    else:
        return list_quantity
    
def WEIGHT(text):
    text = text.lower()
    regex = "(\d+(?:[=\s]mg|[=\s]g|[=\s]kg|[=\s]lb|[=\s]milligram|[=\s]gram|[=\s]kilogram|[=\s]pound|[=\s]tonne|[=\s]quintal|[=\s]milligrams|[=\s]grams|[=\s]kilograms|[=\s]pounds|[=\s]tonnes|[=\s]quintals))|(\d+(?:mg|g|kg|lb|milligram|gram|kilogram|pound|tonne|quintal|milligrams|grams|kilograms|pounds|tonnes|quintals))"
    weight = re.findall(regex, text)
    weight = [j for i in weight for j in i if j]
    list_weight = []
    if len(weight) > 0:
        dict_weight = {}
        dict_weight['@sys.unit-weight'] = [i.lower() for i in weight]
        list_weight.append(dict_weight)
        return list_weight
    else:
        return list_weight
    
def LENGTH(text):
    text = text.lower()
    regex = "(\d+(?:[=\s]mm|[=\s]cm|[=\s]m|[=\s]km|[=\s]millimetre|[=\s]centimetre|[=\s]metre|[=\s]kilometre|[=\s]inch|[=\s]foot|[=\s]feet|[=\s]millimetres|[=\s]centimetres|[=\s]metres|[=\s]kilometres|[=\s]inches|[=\s]foots|[=\s]feets))|(\d+(?:mm|cm|m|km|millimetre|centimetre|metre|kilometre|inch|foot|feet|millimetres|centimetres|metres|kilometres|inches|foots|feets))"
    length = re.findall(regex, text)
    length = [j for i in length for j in i if j]
    list_length = []
    if len(length) > 0:
        dict_length = {}
        dict_length['@sys.unit-length'] = [i.lower() for i in length]
        list_length.append(dict_length)
        return list_length
    else:
        return list_length
    
def ORDINAL(text):
    doc = nlp(text.title())
    ordinal = [ent.text for ent in doc.ents if ent.label_ == 'ORDINAL']
    list_ordinal = []
    if len(ordinal) > 0:
        dict_ordinal = {}
        dict_ordinal['@sys.ordinal'] = [i.lower() for i in ordinal]
        list_ordinal.append(dict_ordinal)
        return list_ordinal
    else:
        return list_ordinal
    
def CARDINAL(text):
    doc = nlp(text.title())
    cardinal = [ent.text for ent in doc.ents if ent.label_ == 'CARDINAL']
    list_cardinal = []
    if len(cardinal) > 0:
        dict_cardinal = {}
        dict_cardinal['@sys.cardinal'] = [i.lower() for i in cardinal]
        list_cardinal.append(dict_cardinal)
        return list_cardinal
    else:
        return list_cardinal

def FULLADDRESS(text):
    text = text.upper()
    regex = "[0-9]{1,3} .+, .+, [A-Z]{1,4} [0-9]{1,7}"
    address = re.findall(regex, text)
    list_address = []
    if len(address) > 0:
        dict_address = {}
        dict_address['@sys.address'] = [i.lower() for i in address]
        list_address.append(dict_address)
        return list_address
    else:
        return list_address
    
def STREETADDRESS(text):
    text = text.lower()
    regex = re.compile("\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)", re.IGNORECASE)
    address = re.findall(regex, text)
    list_address = []
    if len(address) > 0:
        dict_address = {}
        dict_address['@sys.street-address'] = [i.lower() for i in address]
        list_address.append(dict_address)
        return list_address
    else:
        return list_address

def PHONENUMBER(text):
    text = text.lower()
    regex = re.compile("((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))")
    phone = re.findall(regex, text)
    list_phone = []
    if len(phone) > 0:
        dict_phone = {}
        dict_phone['@sys.phone-number'] = [i.lower() for i in phone]
        list_phone.append(dict_phone)
        return list_phone
    else:
        return list_phone
    
def EMAIL(text):
    text = text.lower()
    regex = re.compile("([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)", re.IGNORECASE)
    email = re.findall(regex, text)
    list_email = []
    if len(email) > 0:
        dict_email = {}
        dict_email['@sys.email'] = [i.lower() for i in email]
        list_email.append(dict_email)
        return list_email
    else:
        return list_email
    
def LINKS(text):
    text = text.lower()
    regex = re.compile(u'(?i)((?:https?://|www\d{0,3}[.])?[a-z0-9.\-]+[.](?:(?:international)|(?:construction)|(?:contractors)|(?:enterprises)|(?:photography)|(?:immobilien)|(?:management)|(?:technology)|(?:directory)|(?:education)|(?:equipment)|(?:institute)|(?:marketing)|(?:solutions)|(?:builders)|(?:clothing)|(?:computer)|(?:democrat)|(?:diamonds)|(?:graphics)|(?:holdings)|(?:lighting)|(?:plumbing)|(?:training)|(?:ventures)|(?:academy)|(?:careers)|(?:company)|(?:domains)|(?:florist)|(?:gallery)|(?:guitars)|(?:holiday)|(?:kitchen)|(?:recipes)|(?:shiksha)|(?:singles)|(?:support)|(?:systems)|(?:agency)|(?:berlin)|(?:camera)|(?:center)|(?:coffee)|(?:estate)|(?:kaufen)|(?:luxury)|(?:monash)|(?:museum)|(?:photos)|(?:repair)|(?:social)|(?:tattoo)|(?:travel)|(?:viajes)|(?:voyage)|(?:build)|(?:cheap)|(?:codes)|(?:dance)|(?:email)|(?:glass)|(?:house)|(?:ninja)|(?:photo)|(?:shoes)|(?:solar)|(?:today)|(?:aero)|(?:arpa)|(?:asia)|(?:bike)|(?:buzz)|(?:camp)|(?:club)|(?:coop)|(?:farm)|(?:gift)|(?:guru)|(?:info)|(?:jobs)|(?:kiwi)|(?:land)|(?:limo)|(?:link)|(?:menu)|(?:mobi)|(?:moda)|(?:name)|(?:pics)|(?:pink)|(?:post)|(?:rich)|(?:ruhr)|(?:sexy)|(?:tips)|(?:wang)|(?:wien)|(?:zone)|(?:biz)|(?:cab)|(?:cat)|(?:ceo)|(?:com)|(?:edu)|(?:gov)|(?:int)|(?:mil)|(?:net)|(?:onl)|(?:org)|(?:pro)|(?:red)|(?:tel)|(?:uno)|(?:xxx)|(?:ac)|(?:ad)|(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cu)|(?:cv)|(?:cw)|(?:cx)|(?:cy)|(?:cz)|(?:de)|(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:st)|(?:su)|(?:sv)|(?:sx)|(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:za)|(?:zm)|(?:zw))(?:/[^\s()<>]+[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019])?)', re.IGNORECASE)
    link = re.findall(regex, text)
    list_link = []
    if len(link) > 0:
        dict_link = {}
        dict_link['@sys.url'] = [i.lower() for i in link]
        list_link.append(dict_link)
        return list_link
    else:
        return list_link
    
def DATE(text):
    text = text.lower()
    regex = re.compile(u'(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}', re.IGNORECASE)
    date = re.findall(regex, text)
    list_date = []
    if len(date) > 0:
        dict_date = {}
        dict_date['@sys.date'] = [i.lower() for i in date]
        list_date.append(dict_date)
        return list_date
    elif len(date) == 0:
        for key, value in Date.items():
            for i in value:
                match = re.compile(r"\b%s\b"%(i))
                date = match.findall(text)
                if len(date) != 0:
                    dict_date = {}
                    dict_date['@sys.date'] = [key.lower()]
                    list_date.append(dict_date)
        return list_date
    else:
        return list_date
    
def TIME(text):
    text = text.lower()
    regex = re.compile('\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?', re.IGNORECASE)
    time = re.findall(regex, text)
    list_time = []
    if len(time) > 0:
        dict_time = {}
        dict_time['@sys.time'] = [i.lower() for i in time]
        list_time.append(dict_time)
        return list_time
    else:
        return list_time
    
def ZIP(text):
    text = text.lower()
    regex = re.compile(r'\b\d{5,6}(?:[-\s]\d{4})?\b')
    zipcode = re.findall(regex, text)
    list_zipcode = []
    if len(zipcode) > 0:
        dict_zipcode = {}
        dict_zipcode['@sys.zip-code'] = [i.lower() for i in zipcode]
        list_zipcode.append(dict_zipcode)
        return list_zipcode
    else:
        return list_zipcode
    
def BITCOINADDRESS(text):
    text = text.lower()
    regex = re.compile('(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])')
    addr = re.findall(regex, text)
    list_addr = []
    if len(addr) > 0:
        dict_addr = {}
        dict_addr['@sys.bitcoin-address'] = [i.lower() for i in addr]
        list_addr.append(dict_addr)
        return list_addr
    else:
        return list_addr
    
def CREDITCARD(text):
    text = text.lower()
    regex = re.compile('((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])')
    details = re.findall(regex, text)
    list_details = []
    if len(details) > 0:
        dict_details = {}
        dict_details['@sys.credit-card-number'] = [i.lower() for i in details]
        list_details.append(dict_details)
        return list_details
    else:
        return list_details
    
def IP(text):
    text = text.lower()
    regex = re.compile(u'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', re.IGNORECASE)
    ip = re.findall(regex, text)
    list_ip = []
    if len(ip) > 0:
        dict_ip = {}
        dict_ip['@sys.ip'] = [i.lower() for i in ip]
        list_ip.append(dict_ip)
        return list_ip
    else:
        return list_ip
    
def IPV6(text):
    text = text.lower()
    regex = re.compile(u'\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*', re.VERBOSE|re.IGNORECASE|re.DOTALL)
    ip = re.findall(regex, text)
    list_ip = []
    if len(ip) > 0:
        dict_ip = {}
        dict_ip['@sys.ipv6'] = [i.lower() for i in ip]
        list_ip.append(dict_ip)
        return list_ip
    else:
        return list_ip
    
def COLOR(text):
    text = text.lower()
    color = [i for i in text.split() if i in webcolors.CSS3_NAMES_TO_HEX]
    list_color = []
    if len(color) > 0:
        dict_color = {}
        dict_color['@sys.color'] = [i.lower() for i in color]
        list_color.append(dict_color)
        return list_color
    else:
        return list_color

def TEMPERATURE(text):
    text = text.lower()
    regex = re.compile("(\d+(?:[=\s]degree celsius|[=\s]deg celsius|[=\s]deg c|[=\s]fahrenheit|[=\s]degree fahrenheit|[=\s]deg fahrenheit|[=\s]deg f))|(\d+(?:degree celsius|deg celsius|deg c|fahrenheit|degree fahrenheit|deg fahrenheit|deg f))", re.IGNORECASE)
    temp = re.findall(regex, text)
    temp = [j for i in temp for j in i if j]
    list_temp = []
    if len(temp) > 0:
        dict_temp = {}
        dict_temp['@sys.temperature'] = [i.lower() for i in temp]
        list_temp.append(dict_temp)
        return list_temp
    else:
        return list_temp
    
def entities(text):
    response = {}
    response['parameters'] = []
    try:
        response['parameters'].extend(PERSON(text))
        response['parameters'].extend(GPE(text))
        response['parameters'].extend(NORP(text))
        response['parameters'].extend(FACILITY(text))
        response['parameters'].extend(ORG(text))
        response['parameters'].extend(LOC(text))
        response['parameters'].extend(PRODUCT(text))
        response['parameters'].extend(EVENT(text))
        response['parameters'].extend(WORK_OF_ART(text))
        response['parameters'].extend(LAW(text))
        response['parameters'].extend(LANGUAGE(text))
        response['parameters'].extend(PERCENT(text))
        response['parameters'].extend(MONEY(text))
        response['parameters'].extend(QUANTITY(text))
        response['parameters'].extend(WEIGHT(text))
        response['parameters'].extend(LENGTH(text))
        response['parameters'].extend(ORDINAL(text))
        response['parameters'].extend(CARDINAL(text))
        response['parameters'].extend(FULLADDRESS(text))
        response['parameters'].extend(STREETADDRESS(text))
        response['parameters'].extend(PHONENUMBER(text))
        response['parameters'].extend(EMAIL(text))
        response['parameters'].extend(LINKS(text))
        response['parameters'].extend(DATE(text))
        response['parameters'].extend(TIME(text))
        response['parameters'].extend(ZIP(text))
        response['parameters'].extend(BITCOINADDRESS(text))
        response['parameters'].extend(CREDITCARD(text))
        response['parameters'].extend(IP(text))
        response['parameters'].extend(IPV6(text))
        response['parameters'].extend(COLOR(text))
        response['parameters'].extend(TEMPERATURE(text))
        return response
    except:
        return response
