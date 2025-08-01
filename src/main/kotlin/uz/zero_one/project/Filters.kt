package uz.zero_one.project

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(private val jwtService: JwtService, ): OncePerRequestFilter(){

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authorization = request.getHeader("Authorization")
        if (authorization == null || !authorization.startsWith("Bearer ")){
            filterChain.doFilter(request,response)
            return
        }
        val token = authorization.substring(7)

        jwtService.validateAccessToken(token)
        val claims = jwtService.accessTokenClaims(token)
        val username = claims.subject
        val role = claims["role"] as String
        val userId = (claims["userId"] as Int).toLong()
        val authorities = mutableSetOf<GrantedAuthority>()
        authorities.add(SimpleGrantedAuthority("ROLE_$role"))
        val auth = UsernamePasswordAuthenticationToken(username, token, authorities)
        auth.details = userId
        SecurityContextHolder.getContext().authentication = auth
        filterChain.doFilter(request, response)
    }

}