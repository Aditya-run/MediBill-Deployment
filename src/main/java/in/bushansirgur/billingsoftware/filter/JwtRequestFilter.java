package in.bushansirgur.billingsoftware.filter;

import in.bushansirgur.billingsoftware.service.impl.AppUserDetailsService;
import in.bushansirgur.billingsoftware.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod; // <--- IMPORTANT: Add this import
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AppUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // --- ADD THIS BLOCK ---
        // For CORS preflight requests (OPTIONS method), just let them pass through.
        // They do not carry Authorization headers and are handled by Spring Security's
        // CORS configuration and permitAll() rule.
        if (HttpMethod.OPTIONS.matches(request.getMethod())) {
            filterChain.doFilter(request, response);
            return; // Important: terminate filter execution for OPTIONS
        }
        // ----------------------

        final String authorizationHeader = request.getHeader("Authorization");

        String email = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            // You might want to add try-catch blocks here for jwtUtil.extractUsername
            // to handle ExpiredJwtException or SignatureException gracefully,
            // as you would for other errors.
            try {
                email = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                // Log the exception, e.g., jwtUtil.extractUsername failed
                // For production, you might want to return an Unauthorized/Bad Request directly here
                logger.warn("JWT token extraction failed: " + e.getMessage());
                // Optionally, don't proceed with authentication for this request
                // but still call filterChain.doFilter to allow subsequent filters/security to handle
            }
        }

        // Only attempt authentication if an email was extracted and no authentication is currently set
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            // This validateToken also might throw exceptions; consider try-catch here too.
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response); // Continue the filter chain
    }
}