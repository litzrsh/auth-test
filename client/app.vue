<template>
  <div>
    <h1>Welcome!</h1>
    <div v-if="user">

    </div>
    <button v-else type="button" @click="login">
      Login
    </button>
  </div>
</template>

<script setup lang="ts">
const config = useRuntimeConfig()
console.log(config)

const login = springLogin
const user = await springUser()
</script>
