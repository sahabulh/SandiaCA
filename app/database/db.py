from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

MONGO_DETAILS = "mongodb://root:example@mongo:27017"

db_client = None
database = None

async def connect_and_init_db():
    global db_client
    global database
    db_client = AsyncIOMotorClient(MONGO_DETAILS)
    database = db_client["sandia_ca"]
    print('Connected to mongo.')


async def close_db():
    global db_client
    if db_client is None:
        print('No database connection is present, nothing to close.')
        return
    db_client.close()
    db_client = None
    print('Mongo connection closed.')

async def insert(data: dict, collection_name: str):
    collection = database.get_collection(collection_name)
    document = await collection.insert_one(data)
    return document.inserted_id

async def find(query: dict, collection_name: str):
    collection = database.get_collection(collection_name)
    data = await collection.find_one(query, projection={'_id': False})
    return data

async def update(query: dict, value: dict, collection_name: str):
    collection = database.get_collection(collection_name)
    return await collection.find_one_and_update(query, {'$set': value}, projection={'_id': False}, return_document = ReturnDocument.AFTER)