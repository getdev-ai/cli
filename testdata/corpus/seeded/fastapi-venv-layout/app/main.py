from fastapi import FastAPI
import typed_lib
import fake_analytics_sdk_abc

app = FastAPI()

typed_lib.real_fn()
